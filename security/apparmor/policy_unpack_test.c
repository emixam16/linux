// SPDX-License-Identifier: GPL-2.0-only
/*
 * KUnit tests for AppArmor's policy unpack.
 */

#include <kunit/test.h>
#include <kunit/visibility.h>

#include "include/policy.h"
#include "include/policy_unpack.h"

#include <linux/limits.h>
#include <linux/sizes.h>
#include <linux/unaligned.h>

#define TEST_STRING_NAME "TEST_STRING"
#define TEST_STRING_DATA "testing"
#define TEST_STRING_BUF_OFFSET \
	(3 + strlen(TEST_STRING_NAME) + 1)

#define TEST_U32_NAME "U32_TEST"
#define TEST_U32_DATA ((u32)0x01020304)
#define TEST_NAMED_U32_BUF_OFFSET \
	(TEST_STRING_BUF_OFFSET + 3 + strlen(TEST_STRING_DATA) + 1)
#define TEST_U32_BUF_OFFSET \
	(TEST_NAMED_U32_BUF_OFFSET + 3 + strlen(TEST_U32_NAME) + 1)

#define TEST_U16_OFFSET (TEST_U32_BUF_OFFSET + 3)
#define TEST_U16_DATA ((u16)(TEST_U32_DATA >> 16))

#define TEST_U64_NAME "U64_TEST"
#define TEST_U64_DATA ((u64)0x0102030405060708)
#define TEST_NAMED_U64_BUF_OFFSET (TEST_U32_BUF_OFFSET + sizeof(u32) + 1)
#define TEST_U64_BUF_OFFSET \
	(TEST_NAMED_U64_BUF_OFFSET + 3 + strlen(TEST_U64_NAME) + 1)

#define TEST_BLOB_NAME "BLOB_TEST"
#define TEST_BLOB_DATA "\xde\xad\x00\xbe\xef"
#define TEST_BLOB_DATA_SIZE (ARRAY_SIZE(TEST_BLOB_DATA))
#define TEST_NAMED_BLOB_BUF_OFFSET (TEST_U64_BUF_OFFSET + sizeof(u64) + 1)
#define TEST_BLOB_BUF_OFFSET \
	(TEST_NAMED_BLOB_BUF_OFFSET + 3 + strlen(TEST_BLOB_NAME) + 1)

#define TEST_ARRAY_NAME "ARRAY_TEST"
#define TEST_ARRAY_SIZE 16
#define TEST_NAMED_ARRAY_BUF_OFFSET \
	(TEST_BLOB_BUF_OFFSET + 5 + TEST_BLOB_DATA_SIZE)
#define TEST_ARRAY_BUF_OFFSET \
	(TEST_NAMED_ARRAY_BUF_OFFSET + 3 + strlen(TEST_ARRAY_NAME) + 1)

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

struct policy_unpack_fixture {
	struct aa_ext *e;
	size_t e_size;
};

static struct aa_ext *build_aa_ext_struct(struct policy_unpack_fixture *puf,
					  struct kunit *test, size_t buf_size)
{
	char *buf;
	struct aa_ext *e;

	buf = kunit_kzalloc(test, buf_size, GFP_USER);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, buf);

	e = kunit_kmalloc(test, sizeof(*e), GFP_USER);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, e);

	e->start = buf;
	e->end = e->start + buf_size;
	e->pos = e->start;

	*buf = AA_NAME;
	*(buf + 1) = strlen(TEST_STRING_NAME) + 1;
	strscpy(buf + 3, TEST_STRING_NAME, e->end - (void *)(buf + 3));

	buf = e->start + TEST_STRING_BUF_OFFSET;
	*buf = AA_STRING;
	*(buf + 1) = strlen(TEST_STRING_DATA) + 1;
	strscpy(buf + 3, TEST_STRING_DATA, e->end - (void *)(buf + 3));
	buf = e->start + TEST_NAMED_U32_BUF_OFFSET;
	*buf = AA_NAME;
	*(buf + 1) = strlen(TEST_U32_NAME) + 1;
	strscpy(buf + 3, TEST_U32_NAME, e->end - (void *)(buf + 3));
	*(buf + 3 + strlen(TEST_U32_NAME) + 1) = AA_U32;
	put_unaligned_le32(TEST_U32_DATA, buf + 3 + strlen(TEST_U32_NAME) + 2);

	buf = e->start + TEST_NAMED_U64_BUF_OFFSET;
	*buf = AA_NAME;
	*(buf + 1) = strlen(TEST_U64_NAME) + 1;
	strscpy(buf + 3, TEST_U64_NAME, e->end - (void *)(buf + 3));
	*(buf + 3 + strlen(TEST_U64_NAME) + 1) = AA_U64;
	*((__le64 *)(buf + 3 + strlen(TEST_U64_NAME) + 2)) = cpu_to_le64(TEST_U64_DATA);

	buf = e->start + TEST_NAMED_BLOB_BUF_OFFSET;
	*buf = AA_NAME;
	*(buf + 1) = strlen(TEST_BLOB_NAME) + 1;
	strscpy(buf + 3, TEST_BLOB_NAME, e->end - (void *)(buf + 3));
	*(buf + 3 + strlen(TEST_BLOB_NAME) + 1) = AA_BLOB;
	*(buf + 3 + strlen(TEST_BLOB_NAME) + 2) = TEST_BLOB_DATA_SIZE;
	memcpy(buf + 3 + strlen(TEST_BLOB_NAME) + 6,
		TEST_BLOB_DATA, TEST_BLOB_DATA_SIZE);

	buf = e->start + TEST_NAMED_ARRAY_BUF_OFFSET;
	*buf = AA_NAME;
	*(buf + 1) = strlen(TEST_ARRAY_NAME) + 1;
	strscpy(buf + 3, TEST_ARRAY_NAME, e->end - (void *)(buf + 3));
	*(buf + 3 + strlen(TEST_ARRAY_NAME) + 1) = AA_ARRAY;
	put_unaligned_le16(TEST_ARRAY_SIZE, buf + 3 + strlen(TEST_ARRAY_NAME) + 2);

	return e;
}

static int policy_unpack_test_init(struct kunit *test)
{
	size_t e_size = TEST_ARRAY_BUF_OFFSET + sizeof(u16) + 1;
	struct policy_unpack_fixture *puf;

	puf = kunit_kmalloc(test, sizeof(*puf), GFP_USER);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, puf);

	puf->e_size = e_size;
	puf->e = build_aa_ext_struct(puf, test, e_size);

	test->priv = puf;
	return 0;
}

static void policy_unpack_test_inbounds_when_inbounds(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;

	KUNIT_EXPECT_TRUE(test, aa_inbounds(puf->e, 0));
	KUNIT_EXPECT_TRUE(test, aa_inbounds(puf->e, puf->e_size / 2));
	KUNIT_EXPECT_TRUE(test, aa_inbounds(puf->e, puf->e_size));
}

static void policy_unpack_test_inbounds_when_out_of_bounds(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;

	KUNIT_EXPECT_FALSE(test, aa_inbounds(puf->e, puf->e_size + 1));
}

static void policy_unpack_test_unpack_array_with_null_name(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	u16 array_size = 0;

	puf->e->pos += TEST_ARRAY_BUF_OFFSET;

	KUNIT_EXPECT_TRUE(test, aa_unpack_array(puf->e, NULL, &array_size));
	KUNIT_EXPECT_EQ(test, array_size, (u16)TEST_ARRAY_SIZE);
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos,
		puf->e->start + TEST_ARRAY_BUF_OFFSET + sizeof(u16) + 1);
}

static void policy_unpack_test_unpack_array_with_name(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	const char name[] = TEST_ARRAY_NAME;
	u16 array_size = 0;

	puf->e->pos += TEST_NAMED_ARRAY_BUF_OFFSET;

	KUNIT_EXPECT_TRUE(test, aa_unpack_array(puf->e, name, &array_size));
	KUNIT_EXPECT_EQ(test, array_size, (u16)TEST_ARRAY_SIZE);
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos,
		puf->e->start + TEST_ARRAY_BUF_OFFSET + sizeof(u16) + 1);
}

static void policy_unpack_test_unpack_array_out_of_bounds(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	const char name[] = TEST_ARRAY_NAME;
	u16 array_size;

	puf->e->pos += TEST_NAMED_ARRAY_BUF_OFFSET;
	puf->e->end = puf->e->start + TEST_ARRAY_BUF_OFFSET + sizeof(u16);

	KUNIT_EXPECT_FALSE(test, aa_unpack_array(puf->e, name, &array_size));
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos,
		puf->e->start + TEST_NAMED_ARRAY_BUF_OFFSET);
}

static void policy_unpack_test_unpack_blob_with_null_name(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	char *blob = NULL;
	size_t size;

	puf->e->pos += TEST_BLOB_BUF_OFFSET;
	size = aa_unpack_blob(puf->e, &blob, NULL);

	KUNIT_ASSERT_EQ(test, size, TEST_BLOB_DATA_SIZE);
	KUNIT_EXPECT_TRUE(test,
		memcmp(blob, TEST_BLOB_DATA, TEST_BLOB_DATA_SIZE) == 0);
}

static void policy_unpack_test_unpack_blob_with_name(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	char *blob = NULL;
	size_t size;

	puf->e->pos += TEST_NAMED_BLOB_BUF_OFFSET;
	size = aa_unpack_blob(puf->e, &blob, TEST_BLOB_NAME);

	KUNIT_ASSERT_EQ(test, size, TEST_BLOB_DATA_SIZE);
	KUNIT_EXPECT_TRUE(test,
		memcmp(blob, TEST_BLOB_DATA, TEST_BLOB_DATA_SIZE) == 0);
}

static void policy_unpack_test_unpack_blob_out_of_bounds(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	char *blob = NULL;
	void *start;
	int size;

	puf->e->pos += TEST_NAMED_BLOB_BUF_OFFSET;
	start = puf->e->pos;
	puf->e->end = puf->e->start + TEST_BLOB_BUF_OFFSET
		+ TEST_BLOB_DATA_SIZE - 1;

	size = aa_unpack_blob(puf->e, &blob, TEST_BLOB_NAME);

	KUNIT_EXPECT_EQ(test, size, 0);
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos, start);
}

static void policy_unpack_test_unpack_str_with_null_name(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	const char *string = NULL;
	size_t size;

	puf->e->pos += TEST_STRING_BUF_OFFSET;
	size = aa_unpack_str(puf->e, &string, NULL);

	KUNIT_EXPECT_EQ(test, size, strlen(TEST_STRING_DATA) + 1);
	KUNIT_EXPECT_STREQ(test, string, TEST_STRING_DATA);
}

static void policy_unpack_test_unpack_str_with_name(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	const char *string = NULL;
	size_t size;

	size = aa_unpack_str(puf->e, &string, TEST_STRING_NAME);

	KUNIT_EXPECT_EQ(test, size, strlen(TEST_STRING_DATA) + 1);
	KUNIT_EXPECT_STREQ(test, string, TEST_STRING_DATA);
}

static void policy_unpack_test_unpack_str_out_of_bounds(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	const char *string = NULL;
	void *start = puf->e->pos;
	int size;

	puf->e->end = puf->e->pos + TEST_STRING_BUF_OFFSET
		+ strlen(TEST_STRING_DATA) - 1;

	size = aa_unpack_str(puf->e, &string, TEST_STRING_NAME);

	KUNIT_EXPECT_EQ(test, size, 0);
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos, start);
}

static void policy_unpack_test_unpack_strdup_with_null_name(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	char *string = NULL;
	size_t size;

	puf->e->pos += TEST_STRING_BUF_OFFSET;
	size = aa_unpack_strdup(puf->e, &string, NULL);

	KUNIT_EXPECT_EQ(test, size, strlen(TEST_STRING_DATA) + 1);
	KUNIT_EXPECT_FALSE(test,
			   ((uintptr_t)puf->e->start <= (uintptr_t)string)
			   && ((uintptr_t)string <= (uintptr_t)puf->e->end));
	KUNIT_EXPECT_STREQ(test, string, TEST_STRING_DATA);

	kfree(string);
}

static void policy_unpack_test_unpack_strdup_with_name(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	char *string = NULL;
	size_t size;

	size = aa_unpack_strdup(puf->e, &string, TEST_STRING_NAME);

	KUNIT_EXPECT_EQ(test, size, strlen(TEST_STRING_DATA) + 1);
	KUNIT_EXPECT_FALSE(test,
			   ((uintptr_t)puf->e->start <= (uintptr_t)string)
			   && ((uintptr_t)string <= (uintptr_t)puf->e->end));
	KUNIT_EXPECT_STREQ(test, string, TEST_STRING_DATA);

	kfree(string);
}

static void policy_unpack_test_unpack_strdup_out_of_bounds(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	void *start = puf->e->pos;
	char *string = NULL;
	int size;

	puf->e->end = puf->e->pos + TEST_STRING_BUF_OFFSET
		+ strlen(TEST_STRING_DATA) - 1;

	size = aa_unpack_strdup(puf->e, &string, TEST_STRING_NAME);

	KUNIT_EXPECT_EQ(test, size, 0);
	KUNIT_EXPECT_NULL(test, string);
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos, start);

	kfree(string);
}

static void policy_unpack_test_unpack_nameX_with_null_name(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	bool success;

	puf->e->pos += TEST_U32_BUF_OFFSET;

	success = aa_unpack_nameX(puf->e, AA_U32, NULL);

	KUNIT_EXPECT_TRUE(test, success);
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos,
			    puf->e->start + TEST_U32_BUF_OFFSET + 1);
}

static void policy_unpack_test_unpack_nameX_with_wrong_code(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	bool success;

	puf->e->pos += TEST_U32_BUF_OFFSET;

	success = aa_unpack_nameX(puf->e, AA_BLOB, NULL);

	KUNIT_EXPECT_FALSE(test, success);
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos,
			    puf->e->start + TEST_U32_BUF_OFFSET);
}

static void policy_unpack_test_unpack_nameX_with_name(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	const char name[] = TEST_U32_NAME;
	bool success;

	puf->e->pos += TEST_NAMED_U32_BUF_OFFSET;

	success = aa_unpack_nameX(puf->e, AA_U32, name);

	KUNIT_EXPECT_TRUE(test, success);
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos,
			    puf->e->start + TEST_U32_BUF_OFFSET + 1);
}

static void policy_unpack_test_unpack_nameX_with_wrong_name(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	static const char name[] = "12345678";
	bool success;

	puf->e->pos += TEST_NAMED_U32_BUF_OFFSET;

	success = aa_unpack_nameX(puf->e, AA_U32, name);

	KUNIT_EXPECT_FALSE(test, success);
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos,
			    puf->e->start + TEST_NAMED_U32_BUF_OFFSET);
}

static void policy_unpack_test_unpack_u16_chunk_basic(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	char *chunk = NULL;
	size_t size;

	puf->e->pos += TEST_U16_OFFSET;
	/*
	 * WARNING: For unit testing purposes, we're pushing puf->e->end past
	 * the end of the allocated memory. Doing anything other than comparing
	 * memory addresses is dangerous.
	 */
	puf->e->end += TEST_U16_DATA;

	size = aa_unpack_u16_chunk(puf->e, &chunk);

	KUNIT_EXPECT_PTR_EQ(test, chunk,
			    puf->e->start + TEST_U16_OFFSET + 2);
	KUNIT_EXPECT_EQ(test, size, TEST_U16_DATA);
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos, (chunk + TEST_U16_DATA));
}

static void policy_unpack_test_unpack_u16_chunk_out_of_bounds_1(
		struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	char *chunk = NULL;
	size_t size;

	puf->e->pos = puf->e->end - 1;

	size = aa_unpack_u16_chunk(puf->e, &chunk);

	KUNIT_EXPECT_EQ(test, size, 0);
	KUNIT_EXPECT_NULL(test, chunk);
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos, puf->e->end - 1);
}

static void policy_unpack_test_unpack_u16_chunk_out_of_bounds_2(
		struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	char *chunk = NULL;
	size_t size;

	puf->e->pos += TEST_U16_OFFSET;
	/*
	 * WARNING: For unit testing purposes, we're pushing puf->e->end past
	 * the end of the allocated memory. Doing anything other than comparing
	 * memory addresses is dangerous.
	 */
	puf->e->end = puf->e->pos + TEST_U16_DATA - 1;

	size = aa_unpack_u16_chunk(puf->e, &chunk);

	KUNIT_EXPECT_EQ(test, size, 0);
	KUNIT_EXPECT_NULL(test, chunk);
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos, puf->e->start + TEST_U16_OFFSET);
}

static void policy_unpack_test_unpack_u32_with_null_name(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	bool success;
	u32 data = 0;

	puf->e->pos += TEST_U32_BUF_OFFSET;

	success = aa_unpack_u32(puf->e, &data, NULL);

	KUNIT_EXPECT_TRUE(test, success);
	KUNIT_EXPECT_EQ(test, data, TEST_U32_DATA);
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos,
			puf->e->start + TEST_U32_BUF_OFFSET + sizeof(u32) + 1);
}

static void policy_unpack_test_unpack_u32_with_name(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	const char name[] = TEST_U32_NAME;
	bool success;
	u32 data = 0;

	puf->e->pos += TEST_NAMED_U32_BUF_OFFSET;

	success = aa_unpack_u32(puf->e, &data, name);

	KUNIT_EXPECT_TRUE(test, success);
	KUNIT_EXPECT_EQ(test, data, TEST_U32_DATA);
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos,
			puf->e->start + TEST_U32_BUF_OFFSET + sizeof(u32) + 1);
}

static void policy_unpack_test_unpack_u32_out_of_bounds(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	const char name[] = TEST_U32_NAME;
	bool success;
	u32 data = 0;

	puf->e->pos += TEST_NAMED_U32_BUF_OFFSET;
	puf->e->end = puf->e->start + TEST_U32_BUF_OFFSET + sizeof(u32);

	success = aa_unpack_u32(puf->e, &data, name);

	KUNIT_EXPECT_FALSE(test, success);
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos,
			puf->e->start + TEST_NAMED_U32_BUF_OFFSET);
}

static void policy_unpack_test_unpack_u64_with_null_name(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	bool success;
	u64 data = 0;

	puf->e->pos += TEST_U64_BUF_OFFSET;

	success = aa_unpack_u64(puf->e, &data, NULL);

	KUNIT_EXPECT_TRUE(test, success);
	KUNIT_EXPECT_EQ(test, data, TEST_U64_DATA);
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos,
			puf->e->start + TEST_U64_BUF_OFFSET + sizeof(u64) + 1);
}

static void policy_unpack_test_unpack_u64_with_name(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	const char name[] = TEST_U64_NAME;
	bool success;
	u64 data = 0;

	puf->e->pos += TEST_NAMED_U64_BUF_OFFSET;

	success = aa_unpack_u64(puf->e, &data, name);

	KUNIT_EXPECT_TRUE(test, success);
	KUNIT_EXPECT_EQ(test, data, TEST_U64_DATA);
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos,
			puf->e->start + TEST_U64_BUF_OFFSET + sizeof(u64) + 1);
}

static void policy_unpack_test_unpack_u64_out_of_bounds(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	const char name[] = TEST_U64_NAME;
	bool success;
	u64 data = 0;

	puf->e->pos += TEST_NAMED_U64_BUF_OFFSET;
	puf->e->end = puf->e->start + TEST_U64_BUF_OFFSET + sizeof(u64);

	success = aa_unpack_u64(puf->e, &data, name);

	KUNIT_EXPECT_FALSE(test, success);
	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos,
			puf->e->start + TEST_NAMED_U64_BUF_OFFSET);
}

static void policy_unpack_test_unpack_X_code_match(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	bool success = aa_unpack_X(puf->e, AA_NAME);

	KUNIT_EXPECT_TRUE(test, success);
	KUNIT_EXPECT_TRUE(test, puf->e->pos == puf->e->start + 1);
}

static void policy_unpack_test_unpack_X_code_mismatch(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	bool success = aa_unpack_X(puf->e, AA_STRING);

	KUNIT_EXPECT_FALSE(test, success);
	KUNIT_EXPECT_TRUE(test, puf->e->pos == puf->e->start);
}

static void policy_unpack_test_unpack_X_out_of_bounds(struct kunit *test)
{
	struct policy_unpack_fixture *puf = test->priv;
	bool success;

	puf->e->pos = puf->e->end;
	success = aa_unpack_X(puf->e, AA_NAME);

	KUNIT_EXPECT_FALSE(test, success);
}

/*
 * unpack_policyns_block() tests. The "policyns" struct is untrusted wire
 * input, so each malformed shape must be rejected (-EPROTO) with e->pos
 * restored, and only well-formed blocks may return 1.
 *
 * Blocks are built with a cursor-based emitter rather than the fixed-offset
 * fixture above because the wire struct nests and most tests need a slightly
 * different shape.
 */

#define PN_BLOB_SIZE 512

struct pn_blob {
	struct aa_ext e;
	char *pos;
};

static struct pn_blob *pn_blob_alloc(struct kunit *test)
{
	struct pn_blob *b;

	b = kunit_kmalloc(test, sizeof(*b), GFP_USER);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, b);
	b->e.start = kunit_kzalloc(test, PN_BLOB_SIZE, GFP_USER);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, b->e.start);
	b->e.pos = b->e.start;
	b->pos = b->e.start;
	/* e.end is finalized to the written length by pn_blob_seal() */
	b->e.end = b->e.start + PN_BLOB_SIZE;
	return b;
}

static void pn_put_bytes(struct kunit *test, struct pn_blob *b,
			 const void *data, size_t len)
{
	KUNIT_ASSERT_TRUE(test, b->pos + len <= (char *)b->e.end);
	memcpy(b->pos, data, len);
	b->pos += len;
}

static void pn_put_code(struct kunit *test, struct pn_blob *b,
			enum aa_code code)
{
	char c = code;

	pn_put_bytes(test, b, &c, 1);
}

/* u16 length-prefixed chunk of exactly @len bytes of @s (no implicit NUL) */
static void pn_put_chunk_raw(struct kunit *test, struct pn_blob *b,
			     const char *s, u16 len)
{
	KUNIT_ASSERT_TRUE(test, b->pos + 2 <= (char *)b->e.end);
	put_unaligned_le16(len, b->pos);
	b->pos += 2;
	pn_put_bytes(test, b, s, len);
}

/* u16 length-prefixed chunk: the encoding under AA_NAME and AA_STRING */
static void pn_put_chunk(struct kunit *test, struct pn_blob *b, const char *s)
{
	pn_put_chunk_raw(test, b, s, strlen(s) + 1);
}

static void pn_put_name(struct kunit *test, struct pn_blob *b,
			const char *name)
{
	pn_put_code(test, b, AA_NAME);
	pn_put_chunk(test, b, name);
}

static void pn_put_u32(struct kunit *test, struct pn_blob *b, u32 v)
{
	pn_put_code(test, b, AA_U32);
	KUNIT_ASSERT_TRUE(test, b->pos + 4 <= (char *)b->e.end);
	put_unaligned_le32(v, b->pos);
	b->pos += 4;
}

static void pn_put_u64(struct kunit *test, struct pn_blob *b, u64 v)
{
	pn_put_code(test, b, AA_U64);
	KUNIT_ASSERT_TRUE(test, b->pos + 8 <= (char *)b->e.end);
	put_unaligned_le64(v, b->pos);
	b->pos += 8;
}

static void pn_put_array_hdr(struct kunit *test, struct pn_blob *b, u16 count)
{
	pn_put_code(test, b, AA_ARRAY);
	KUNIT_ASSERT_TRUE(test, b->pos + 2 <= (char *)b->e.end);
	put_unaligned_le16(count, b->pos);
	b->pos += 2;
}

/* clamp e->end to what was actually written so overreads go out of bounds */
static void pn_blob_seal(struct pn_blob *b)
{
	b->e.end = b->pos;
}

struct pn_block_shape {
	u32 target;
	u32 scope;
	u32 specified;
	u32 percent;
	u16 array_count;	/* wire count field; values emitted to match */
	u64 value0;		/* first array value; the rest are 0 */
	const char *name;	/* trailing "name" string, or NULL */
	bool structend;
};

#define PN_WELLFORMED_SHAPE {						\
		.target = AA_POLICYNS_TGT_CHILDREN,			\
		.scope = AA_POLICYNS_SCOPE_LOCAL,			\
		.specified = BIT(AA_POLICYNS_KEY_MEMORY),		\
		.array_count = AA_POLICYNS_KEY_MAX,			\
		.value0 = SZ_1M,					\
		.structend = true,					\
	}

static void pn_put_block(struct kunit *test, struct pn_blob *b,
			 const struct pn_block_shape *s)
{
	int i;

	pn_put_name(test, b, "policyns");
	pn_put_code(test, b, AA_STRUCT);
	pn_put_u32(test, b, s->target);
	pn_put_u32(test, b, s->scope);
	pn_put_u32(test, b, s->specified);
	pn_put_u32(test, b, s->percent);
	pn_put_array_hdr(test, b, s->array_count);
	for (i = 0; i < s->array_count; i++)
		pn_put_u64(test, b, i == 0 ? s->value0 : 0);
	pn_put_code(test, b, AA_ARRAYEND);
	if (s->name) {
		pn_put_name(test, b, "name");
		pn_put_code(test, b, AA_STRING);
		pn_put_chunk(test, b, s->name);
	}
	if (s->structend)
		pn_put_code(test, b, AA_STRUCTEND);
}

static void policy_unpack_test_policyns_wellformed(struct kunit *test)
{
	struct pn_block_shape s = PN_WELLFORMED_SHAPE;
	struct pn_blob *b = pn_blob_alloc(test);
	struct aa_ns_budget budget = {};
	int k;

	pn_put_block(test, b, &s);
	pn_blob_seal(b);

	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), 1);
	KUNIT_EXPECT_PTR_EQ(test, b->e.pos, b->e.end);
	KUNIT_EXPECT_EQ(test, budget.target, (u32)AA_POLICYNS_TGT_CHILDREN);
	KUNIT_EXPECT_EQ(test, budget.scope, (u32)AA_POLICYNS_SCOPE_LOCAL);
	KUNIT_EXPECT_EQ(test, budget.specified,
			(u32)BIT(AA_POLICYNS_KEY_MEMORY));
	KUNIT_EXPECT_EQ(test, budget.percent, (u32)0);
	KUNIT_EXPECT_EQ(test, budget.values[AA_POLICYNS_KEY_MEMORY],
			(long)SZ_1M);
	for (k = AA_POLICYNS_KEY_MAX_PROFILE; k < AA_POLICYNS_KEY_MAX; k++)
		KUNIT_EXPECT_EQ(test, budget.values[k], 0L);
	KUNIT_EXPECT_NULL(test, budget.name);
}

static void policy_unpack_test_policyns_absent(struct kunit *test)
{
	struct pn_blob *b = pn_blob_alloc(test);
	struct aa_ns_budget budget = {};

	/* some other named u32, not a policyns struct */
	pn_put_name(test, b, "notpolicyns");
	pn_put_u32(test, b, 1);
	pn_blob_seal(b);

	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), 0);
	KUNIT_EXPECT_PTR_EQ(test, b->e.pos, b->e.start);
}

static void policy_unpack_test_policyns_name_target(struct kunit *test)
{
	struct pn_block_shape s = PN_WELLFORMED_SHAPE;
	struct pn_blob *b = pn_blob_alloc(test);
	struct aa_ns_budget budget = {};

	s.target = AA_POLICYNS_TGT_NAME;
	s.name = "lxd-child";
	pn_put_block(test, b, &s);
	pn_blob_seal(b);

	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), 1);
	KUNIT_ASSERT_NOT_NULL(test, budget.name);
	KUNIT_EXPECT_STREQ(test, budget.name, "lxd-child");
	kfree(budget.name);
}

static void policy_unpack_test_policyns_name_missing(struct kunit *test)
{
	struct pn_block_shape s = PN_WELLFORMED_SHAPE;
	struct pn_blob *b = pn_blob_alloc(test);
	struct aa_ns_budget budget = {};

	/* :NAME: target must carry the name string */
	s.target = AA_POLICYNS_TGT_NAME;
	pn_put_block(test, b, &s);
	pn_blob_seal(b);

	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), -EPROTO);
	KUNIT_EXPECT_PTR_EQ(test, b->e.pos, b->e.start);
}

static void policy_unpack_test_policyns_unexpected_name(struct kunit *test)
{
	struct pn_block_shape s = PN_WELLFORMED_SHAPE;
	struct pn_blob *b = pn_blob_alloc(test);
	struct aa_ns_budget budget = {};

	/* a name string on a non-:NAME: target must not parse */
	s.name = "sneaky";
	pn_put_block(test, b, &s);
	pn_blob_seal(b);

	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), -EPROTO);
	KUNIT_EXPECT_PTR_EQ(test, b->e.pos, b->e.start);
}

static void policy_unpack_test_policyns_short_array(struct kunit *test)
{
	struct pn_block_shape s = PN_WELLFORMED_SHAPE;
	struct pn_blob *b = pn_blob_alloc(test);
	struct aa_ns_budget budget = {};

	s.array_count = AA_POLICYNS_KEY_MAX - 1;
	pn_put_block(test, b, &s);
	pn_blob_seal(b);

	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), -EPROTO);
	KUNIT_EXPECT_PTR_EQ(test, b->e.pos, b->e.start);
}

static void policy_unpack_test_policyns_long_array(struct kunit *test)
{
	struct pn_block_shape s = PN_WELLFORMED_SHAPE;
	struct pn_blob *b = pn_blob_alloc(test);
	struct aa_ns_budget budget = {};

	s.array_count = AA_POLICYNS_KEY_MAX + 1;
	pn_put_block(test, b, &s);
	pn_blob_seal(b);

	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), -EPROTO);
	KUNIT_EXPECT_PTR_EQ(test, b->e.pos, b->e.start);
}

static void policy_unpack_test_policyns_value_over_int_max(struct kunit *test)
{
	struct pn_block_shape s = PN_WELLFORMED_SHAPE;
	struct pn_blob *b = pn_blob_alloc(test);
	struct aa_ns_budget budget = {};

	/* the parser bounds caps at INT_MAX; larger values are rejected */
	s.value0 = (u64)INT_MAX + 1;
	pn_put_block(test, b, &s);
	pn_blob_seal(b);

	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), -EPROTO);
	KUNIT_EXPECT_PTR_EQ(test, b->e.pos, b->e.start);
}

static void policy_unpack_test_policyns_bad_bitmasks(struct kunit *test)
{
	struct pn_block_shape s = PN_WELLFORMED_SHAPE;
	struct pn_blob *b = pn_blob_alloc(test);
	struct aa_ns_budget budget = {};

	s.specified = BIT(AA_POLICYNS_KEY_MAX);
	pn_put_block(test, b, &s);
	pn_blob_seal(b);
	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), -EPROTO);
	KUNIT_EXPECT_PTR_EQ(test, b->e.pos, b->e.start);

	b = pn_blob_alloc(test);
	s.specified = BIT(AA_POLICYNS_KEY_MEMORY);
	s.percent = BIT(AA_POLICYNS_KEY_MAX);
	pn_put_block(test, b, &s);
	pn_blob_seal(b);
	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), -EPROTO);
	KUNIT_EXPECT_PTR_EQ(test, b->e.pos, b->e.start);
}

static void policy_unpack_test_policyns_bad_target_scope(struct kunit *test)
{
	struct pn_block_shape s = PN_WELLFORMED_SHAPE;
	struct pn_blob *b = pn_blob_alloc(test);
	struct aa_ns_budget budget = {};

	/* a target past the last known value must be rejected */
	s.target = AA_POLICYNS_TGT_NAME + 1;
	pn_put_block(test, b, &s);
	pn_blob_seal(b);
	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), -EPROTO);
	KUNIT_EXPECT_PTR_EQ(test, b->e.pos, b->e.start);

	/* likewise a scope past the last known value */
	b = pn_blob_alloc(test);
	s.target = AA_POLICYNS_TGT_CHILDREN;
	s.scope = AA_POLICYNS_SCOPE_SUBTREE + 1;
	pn_put_block(test, b, &s);
	pn_blob_seal(b);
	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), -EPROTO);
	KUNIT_EXPECT_PTR_EQ(test, b->e.pos, b->e.start);
}

static void policy_unpack_test_policyns_missing_structend(struct kunit *test)
{
	struct pn_block_shape s = PN_WELLFORMED_SHAPE;
	struct pn_blob *b = pn_blob_alloc(test);
	struct aa_ns_budget budget = {};

	s.structend = false;
	pn_put_block(test, b, &s);
	pn_blob_seal(b);

	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), -EPROTO);
	KUNIT_EXPECT_PTR_EQ(test, b->e.pos, b->e.start);
}

static void policy_unpack_test_policyns_truncated(struct kunit *test)
{
	struct pn_blob *b = pn_blob_alloc(test);
	struct aa_ns_budget budget = {};
	char *array_start;

	pn_put_name(test, b, "policyns");
	pn_put_code(test, b, AA_STRUCT);
	pn_put_u32(test, b, AA_POLICYNS_TGT_CHILDREN);
	pn_put_u32(test, b, AA_POLICYNS_SCOPE_LOCAL);
	pn_put_u32(test, b, BIT(AA_POLICYNS_KEY_MEMORY));
	pn_put_u32(test, b, 0);
	pn_put_array_hdr(test, b, AA_POLICYNS_KEY_MAX);
	array_start = b->pos;
	pn_put_u64(test, b, SZ_1M);
	/* clip mid-way through the first value's payload */
	b->e.end = array_start + 4;

	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), -EPROTO);
	KUNIT_EXPECT_PTR_EQ(test, b->e.pos, b->e.start);
}

static void policy_unpack_test_policyns_header_truncated(struct kunit *test)
{
	struct pn_blob *b = pn_blob_alloc(test);
	struct aa_ns_budget budget = {};

	/*
	 * Truncation before the AA_STRUCT code reads as "no block here":
	 * return 0, not -EPROTO. unpack_policyns() relies on 0 as its clean
	 * loop-termination contract.
	 */
	pn_put_name(test, b, "policyns");
	pn_blob_seal(b);

	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), 0);
	KUNIT_EXPECT_PTR_EQ(test, b->e.pos, b->e.start);
}

static void policy_unpack_test_policyns_unterminated_name(struct kunit *test)
{
	struct pn_block_shape s = PN_WELLFORMED_SHAPE;
	struct pn_blob *b = pn_blob_alloc(test);
	struct aa_ns_budget budget = {};

	/* a :NAME: string chunk without the trailing NUL must be rejected */
	s.target = AA_POLICYNS_TGT_NAME;
	s.structend = false;
	pn_put_block(test, b, &s);
	pn_put_name(test, b, "name");
	pn_put_code(test, b, AA_STRING);
	pn_put_chunk_raw(test, b, "evil", 4);
	pn_put_code(test, b, AA_STRUCTEND);
	pn_blob_seal(b);

	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), -EPROTO);
	KUNIT_EXPECT_PTR_EQ(test, b->e.pos, b->e.start);
}

static void policy_unpack_test_policyns_sequential_blocks(struct kunit *test)
{
	struct pn_block_shape s = PN_WELLFORMED_SHAPE;
	struct pn_blob *b = pn_blob_alloc(test);
	struct aa_ns_budget budget = {};

	/* two blocks back to back, as unpack_policyns() consumes them */
	pn_put_block(test, b, &s);
	s.target = AA_POLICYNS_TGT_SELF;
	pn_put_block(test, b, &s);
	pn_blob_seal(b);

	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), 1);
	KUNIT_EXPECT_EQ(test, budget.target, (u32)AA_POLICYNS_TGT_CHILDREN);
	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), 1);
	KUNIT_EXPECT_EQ(test, budget.target, (u32)AA_POLICYNS_TGT_SELF);
	KUNIT_EXPECT_EQ(test, unpack_policyns_block(&b->e, &budget), 0);
	KUNIT_EXPECT_PTR_EQ(test, b->e.pos, b->e.end);
}

static struct kunit_case apparmor_policy_unpack_test_cases[] = {
	KUNIT_CASE(policy_unpack_test_inbounds_when_inbounds),
	KUNIT_CASE(policy_unpack_test_inbounds_when_out_of_bounds),
	KUNIT_CASE(policy_unpack_test_unpack_array_with_null_name),
	KUNIT_CASE(policy_unpack_test_unpack_array_with_name),
	KUNIT_CASE(policy_unpack_test_unpack_array_out_of_bounds),
	KUNIT_CASE(policy_unpack_test_unpack_blob_with_null_name),
	KUNIT_CASE(policy_unpack_test_unpack_blob_with_name),
	KUNIT_CASE(policy_unpack_test_unpack_blob_out_of_bounds),
	KUNIT_CASE(policy_unpack_test_unpack_nameX_with_null_name),
	KUNIT_CASE(policy_unpack_test_unpack_nameX_with_wrong_code),
	KUNIT_CASE(policy_unpack_test_unpack_nameX_with_name),
	KUNIT_CASE(policy_unpack_test_unpack_nameX_with_wrong_name),
	KUNIT_CASE(policy_unpack_test_unpack_str_with_null_name),
	KUNIT_CASE(policy_unpack_test_unpack_str_with_name),
	KUNIT_CASE(policy_unpack_test_unpack_str_out_of_bounds),
	KUNIT_CASE(policy_unpack_test_unpack_strdup_with_null_name),
	KUNIT_CASE(policy_unpack_test_unpack_strdup_with_name),
	KUNIT_CASE(policy_unpack_test_unpack_strdup_out_of_bounds),
	KUNIT_CASE(policy_unpack_test_unpack_u16_chunk_basic),
	KUNIT_CASE(policy_unpack_test_unpack_u16_chunk_out_of_bounds_1),
	KUNIT_CASE(policy_unpack_test_unpack_u16_chunk_out_of_bounds_2),
	KUNIT_CASE(policy_unpack_test_unpack_u32_with_null_name),
	KUNIT_CASE(policy_unpack_test_unpack_u32_with_name),
	KUNIT_CASE(policy_unpack_test_unpack_u32_out_of_bounds),
	KUNIT_CASE(policy_unpack_test_unpack_u64_with_null_name),
	KUNIT_CASE(policy_unpack_test_unpack_u64_with_name),
	KUNIT_CASE(policy_unpack_test_unpack_u64_out_of_bounds),
	KUNIT_CASE(policy_unpack_test_unpack_X_code_match),
	KUNIT_CASE(policy_unpack_test_unpack_X_code_mismatch),
	KUNIT_CASE(policy_unpack_test_unpack_X_out_of_bounds),
	KUNIT_CASE(policy_unpack_test_policyns_wellformed),
	KUNIT_CASE(policy_unpack_test_policyns_absent),
	KUNIT_CASE(policy_unpack_test_policyns_name_target),
	KUNIT_CASE(policy_unpack_test_policyns_name_missing),
	KUNIT_CASE(policy_unpack_test_policyns_unexpected_name),
	KUNIT_CASE(policy_unpack_test_policyns_short_array),
	KUNIT_CASE(policy_unpack_test_policyns_long_array),
	KUNIT_CASE(policy_unpack_test_policyns_value_over_int_max),
	KUNIT_CASE(policy_unpack_test_policyns_bad_bitmasks),
	KUNIT_CASE(policy_unpack_test_policyns_bad_target_scope),
	KUNIT_CASE(policy_unpack_test_policyns_missing_structend),
	KUNIT_CASE(policy_unpack_test_policyns_truncated),
	KUNIT_CASE(policy_unpack_test_policyns_header_truncated),
	KUNIT_CASE(policy_unpack_test_policyns_unterminated_name),
	KUNIT_CASE(policy_unpack_test_policyns_sequential_blocks),
	{},
};

static struct kunit_suite apparmor_policy_unpack_test_module = {
	.name = "apparmor_policy_unpack",
	.init = policy_unpack_test_init,
	.test_cases = apparmor_policy_unpack_test_cases,
};

kunit_test_suite(apparmor_policy_unpack_test_module);

MODULE_DESCRIPTION("KUnit tests for AppArmor's policy unpack");
MODULE_LICENSE("GPL");
