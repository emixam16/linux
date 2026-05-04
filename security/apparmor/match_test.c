// SPDX-License-Identifier: GPL-2.0-only
/*
 * KUnit tests for AppArmor's DFA match engine.
 *
 * These tests pin down externally observable behavior of the matcher
 * so that hot-path refactors can be done with confidence. They use
 * the kernel-resident `stacksplitdfa` (see lsm.c), which recognizes
 * the "//&" stack-separator language used by aa_label_str_split().
 */

#include <kunit/test.h>
#include <linux/string.h>

#include "include/lib.h"
#include "include/match.h"

/*
 * Sanity: stacksplitdfa was unpacked at apparmor init time and the
 * required tables are present.
 */
static void test_stacksplitdfa_present(struct kunit *test)
{
	KUNIT_ASSERT_NOT_NULL(test, stacksplitdfa);
	KUNIT_EXPECT_NOT_NULL(test, stacksplitdfa->tables[YYTD_ID_BASE]);
	KUNIT_EXPECT_NOT_NULL(test, stacksplitdfa->tables[YYTD_ID_DEF]);
	KUNIT_EXPECT_NOT_NULL(test, stacksplitdfa->tables[YYTD_ID_NXT]);
	KUNIT_EXPECT_NOT_NULL(test, stacksplitdfa->tables[YYTD_ID_CHK]);
	KUNIT_EXPECT_NOT_NULL(test, stacksplitdfa->tables[YYTD_ID_ACCEPT]);
}

/*
 * aa_dfa_match_until on a string containing the "//&" separator must
 * land in an accepting state and return a position right past the
 * separator. The split helpers in include/label.h depend on this.
 */
static void test_match_until_finds_separator(struct kunit *test)
{
	const char *str = "alpha//&beta";
	const char *pos = NULL;
	aa_state_t state;

	state = aa_dfa_match_until(stacksplitdfa, DFA_START, str, &pos);
	KUNIT_EXPECT_NE(test, state, (aa_state_t)DFA_NOMATCH);
	KUNIT_ASSERT_NOT_NULL(test, pos);
	KUNIT_EXPECT_NE(test, ACCEPT_TABLE(stacksplitdfa)[state], 0u);
	/* pos should sit just after "//&" -- i.e. on 'b' */
	KUNIT_EXPECT_EQ(test, *pos, 'b');
	/* aa_label_str_split convention: separator begins at pos - 3 */
	KUNIT_EXPECT_EQ(test, strncmp(pos - 3, "//&", 3), 0);
}

/*
 * No separator present -- match must consume the whole string and
 * the accept table for the final state must be zero.
 */
static void test_match_until_no_separator(struct kunit *test)
{
	const char *str = "no-separator-here";
	const char *pos = NULL;
	aa_state_t state;

	state = aa_dfa_match_until(stacksplitdfa, DFA_START, str, &pos);
	KUNIT_ASSERT_NOT_NULL(test, pos);
	KUNIT_EXPECT_EQ(test, *pos, '\0');
	KUNIT_EXPECT_EQ(test, ACCEPT_TABLE(stacksplitdfa)[state], 0u);
}

/*
 * aa_dfa_matchn_until honors the byte-count bound; with a length
 * shorter than the full string, no separator may be found even
 * if one exists past the bound.
 */
static void test_matchn_until_respects_n(struct kunit *test)
{
	const char *str = "ab//&cd";
	const char *pos = NULL;
	aa_state_t state;

	/* only see "ab//" -- 4 bytes, no separator yet */
	state = aa_dfa_matchn_until(stacksplitdfa, DFA_START, str, 4, &pos);
	KUNIT_EXPECT_EQ(test, ACCEPT_TABLE(stacksplitdfa)[state], 0u);

	/* extend to full -- separator present */
	pos = NULL;
	state = aa_dfa_matchn_until(stacksplitdfa, DFA_START, str, 7, &pos);
	KUNIT_EXPECT_NE(test, ACCEPT_TABLE(stacksplitdfa)[state], 0u);
}

/*
 * aa_dfa_match and aa_dfa_match_len with the same input must reach
 * the same state. This is the core invariant the optimization series
 * must preserve.
 */
static void test_match_and_match_len_agree(struct kunit *test)
{
	const char *str = "alpha//&beta";
	aa_state_t s1, s2;

	s1 = aa_dfa_match(stacksplitdfa, DFA_START, str);
	s2 = aa_dfa_match_len(stacksplitdfa, DFA_START, str, strlen(str));
	KUNIT_EXPECT_EQ(test, s1, s2);
}

/*
 * Stepping aa_dfa_next char-by-char must reach the same state as
 * aa_dfa_match. This covers the "single-step" entry point that many
 * callers use (mount flags, capability bits, null transitions).
 */
static void test_step_equals_match(struct kunit *test)
{
	const char *str = "alpha//&beta";
	aa_state_t s_step = DFA_START;
	aa_state_t s_bulk;
	const char *p;

	for (p = str; *p; p++)
		s_step = aa_dfa_next(stacksplitdfa, s_step, *p);

	s_bulk = aa_dfa_match(stacksplitdfa, DFA_START, str);
	KUNIT_EXPECT_EQ(test, s_step, s_bulk);
}

/*
 * Starting from DFA_NOMATCH must stay in DFA_NOMATCH regardless of
 * input. This is relied on by call sites that chain matches and
 * propagate failure by passing the prior state in.
 */
static void test_nomatch_is_sticky(struct kunit *test)
{
	const char *str = "anything";
	aa_state_t s;

	s = aa_dfa_match(stacksplitdfa, DFA_NOMATCH, str);
	KUNIT_EXPECT_EQ(test, s, (aa_state_t)DFA_NOMATCH);

	s = aa_dfa_match_len(stacksplitdfa, DFA_NOMATCH, str, strlen(str));
	KUNIT_EXPECT_EQ(test, s, (aa_state_t)DFA_NOMATCH);

	s = aa_dfa_next(stacksplitdfa, DFA_NOMATCH, 'x');
	/* aa_dfa_next does not have the explicit nomatch short-circuit
	 * but match_char with state 0 must immediately fail check[]; the
	 * default of state 0 must also be 0, so we stay at 0.
	 */
	KUNIT_EXPECT_EQ(test, s, (aa_state_t)DFA_NOMATCH);
}

/*
 * aa_dfa_leftmatch must report a non-zero match count when the input
 * traverses through accepting states, and the resulting state must be
 * deterministic across repeated calls.
 */
static void test_leftmatch_deterministic(struct kunit *test)
{
	const char *str = "a//&b//&c";
	unsigned int c1 = 0, c2 = 0;
	aa_state_t s1, s2;

	s1 = aa_dfa_leftmatch(stacksplitdfa, DFA_START, str, &c1);
	s2 = aa_dfa_leftmatch(stacksplitdfa, DFA_START, str, &c2);
	KUNIT_EXPECT_EQ(test, s1, s2);
	KUNIT_EXPECT_EQ(test, c1, c2);
}

/*
 * The empty string must leave the matcher in the start state for
 * aa_dfa_match (which terminates immediately on the NUL) and for
 * aa_dfa_match_len with len == 0.
 */
static void test_empty_input(struct kunit *test)
{
	aa_state_t s;

	s = aa_dfa_match(stacksplitdfa, DFA_START, "");
	KUNIT_EXPECT_EQ(test, s, (aa_state_t)DFA_START);

	s = aa_dfa_match_len(stacksplitdfa, DFA_START, "ignored", 0);
	KUNIT_EXPECT_EQ(test, s, (aa_state_t)DFA_START);
}

/*
 * aa_dfa_next must agree with aa_dfa_match on every single byte. This is
 * the invariant the dense_start[] tables in commit C12 rely on: a dense
 * lookup is "step exactly once from start with this byte". If
 * single-step ever diverges from bulk match, dense_start would silently
 * return wrong perms.
 */
static void test_step_consistent_with_match(struct kunit *test)
{
	int b;

	for (b = 1; b < 128; b++) {
		char buf[2] = { (char)b, '\0' };
		aa_state_t bulk, step;

		bulk = aa_dfa_match(stacksplitdfa, DFA_START, buf);
		step = aa_dfa_next(stacksplitdfa, DFA_START, (char)b);
		KUNIT_EXPECT_EQ(test, bulk, step);
	}
}

/*
 * The 2-byte dense table in commit C18 collapses two single-step
 * transitions into one lookup. Verify the invariant: stepping twice
 * with bytes (b0, b1) agrees with the bulk match of {b0, b1, '\0'}.
 */
static void test_two_step_consistent_with_match(struct kunit *test)
{
	const char *pairs[] = {"//", "ab", "/&", "//&", "x/y"};
	int i;

	for (i = 0; i < ARRAY_SIZE(pairs); i++) {
		const char *p = pairs[i];
		aa_state_t bulk = aa_dfa_match(stacksplitdfa, DFA_START, p);
		aa_state_t s = DFA_START;
		const char *q;

		for (q = p; *q; q++)
			s = aa_dfa_next(stacksplitdfa, s, *q);

		KUNIT_EXPECT_EQ(test, bulk, s);
	}
}

#ifdef CONFIG_SECURITY_APPARMOR_MATCH_CACHE
/*
 * The match cache must never return a stored value across an
 * aa_match_cache_invalidate(); a hit after invalidation would mean a
 * stale permission set after a policy reload. Use a fake aa_policydb
 * pointer (we never dereference it) so the test stays self-contained.
 */
static void test_match_cache_invalidate(struct kunit *test)
{
	struct aa_policydb *fake_pdb = (struct aa_policydb *)&test_match_cache_invalidate;
	const char *name = "/var/log/messages";
	size_t len = strlen(name);
	u32 hash = aa_match_cache_hash(name, len);
	aa_state_t got;

	aa_match_cache_insert(fake_pdb, DFA_START, name, len, hash, 0x4242);
	KUNIT_ASSERT_TRUE(test,
		aa_match_cache_lookup(fake_pdb, DFA_START, name, len, hash, &got));
	KUNIT_EXPECT_EQ(test, got, (aa_state_t)0x4242);

	aa_match_cache_invalidate();
	KUNIT_EXPECT_FALSE(test,
		aa_match_cache_lookup(fake_pdb, DFA_START, name, len, hash, &got));
}

/*
 * Hash collision must not yield a hit; the cache must memcmp the name.
 */
static void test_match_cache_no_collision_leak(struct kunit *test)
{
	struct aa_policydb *fake_pdb = (struct aa_policydb *)&test_match_cache_no_collision_leak;
	const char *a = "alpha";
	const char *b = "beta";
	size_t la = strlen(a), lb = strlen(b);
	u32 ha = aa_match_cache_hash(a, la);
	aa_state_t got;

	aa_match_cache_insert(fake_pdb, DFA_START, a, la, ha, 0x1111);
	/* Look up "beta" but with "alpha"'s hash and length. The memcmp
	 * must reject it.
	 */
	KUNIT_EXPECT_FALSE(test,
		aa_match_cache_lookup(fake_pdb, DFA_START, b, lb, ha, &got));
}
#endif

static struct kunit_case apparmor_match_test_cases[] = {
	KUNIT_CASE(test_stacksplitdfa_present),
	KUNIT_CASE(test_match_until_finds_separator),
	KUNIT_CASE(test_match_until_no_separator),
	KUNIT_CASE(test_matchn_until_respects_n),
	KUNIT_CASE(test_match_and_match_len_agree),
	KUNIT_CASE(test_step_equals_match),
	KUNIT_CASE(test_nomatch_is_sticky),
	KUNIT_CASE(test_leftmatch_deterministic),
	KUNIT_CASE(test_empty_input),
	KUNIT_CASE(test_step_consistent_with_match),
	KUNIT_CASE(test_two_step_consistent_with_match),
#ifdef CONFIG_SECURITY_APPARMOR_MATCH_CACHE
	KUNIT_CASE(test_match_cache_invalidate),
	KUNIT_CASE(test_match_cache_no_collision_leak),
#endif
	{},
};

static struct kunit_suite apparmor_match_test_module = {
	.name = "apparmor_match",
	.test_cases = apparmor_match_test_cases,
};
kunit_test_suite(apparmor_match_test_module);

MODULE_LICENSE("GPL");
