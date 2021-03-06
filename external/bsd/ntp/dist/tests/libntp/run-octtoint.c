/*	$NetBSD: run-octtoint.c,v 1.1.1.2 2015/07/10 13:11:14 christos Exp $	*/

/* AUTOGENERATED FILE. DO NOT EDIT. */

//=======Test Runner Used To Run Each Test Below=====
#define RUN_TEST(TestFunc, TestLineNum) \
{ \
  Unity.CurrentTestName = #TestFunc; \
  Unity.CurrentTestLineNumber = TestLineNum; \
  Unity.NumberOfTests++; \
  if (TEST_PROTECT()) \
  { \
      setUp(); \
      TestFunc(); \
  } \
  if (TEST_PROTECT() && !TEST_IS_IGNORED) \
  { \
    tearDown(); \
  } \
  UnityConcludeTest(); \
}

//=======Automagically Detected Files To Include=====
#include "unity.h"
#include <setjmp.h>
#include <stdio.h>

//=======External Functions This Runner Calls=====
extern void setUp(void);
extern void tearDown(void);
extern void test_SingleDigit(void);
extern void test_MultipleDigits(void);
extern void test_Zero(void);
extern void test_MaximumUnsigned32bit(void);
extern void test_Overflow(void);
extern void test_IllegalCharacter(void);
extern void test_IllegalDigit(void);


//=======Test Reset Option=====
void resetTest()
{
  tearDown();
  setUp();
}

char *progname;


//=======MAIN=====
int main(int argc, char *argv[])
{
  progname = argv[0];
  Unity.TestFile = "octtoint.c";
  UnityBegin("octtoint.c");
  RUN_TEST(test_SingleDigit, 7);
  RUN_TEST(test_MultipleDigits, 15);
  RUN_TEST(test_Zero, 24);
  RUN_TEST(test_MaximumUnsigned32bit, 33);
  RUN_TEST(test_Overflow, 42);
  RUN_TEST(test_IllegalCharacter, 50);
  RUN_TEST(test_IllegalDigit, 58);

  return (UnityEnd());
}
