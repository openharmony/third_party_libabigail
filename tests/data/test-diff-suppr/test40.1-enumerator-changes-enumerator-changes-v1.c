/**
 * compile this with:
 *   gcc -g -c test40.1-enumerator-changes-enumerator-changes-v1.c
 */

enum Enum0
{
  ENUM0_E0,
  ENUM0_E1,
  ENOM0_LAST
};

enum Enum1
{
  ENUM1_E0,
  ENUM1_E1,
  ENUM1_MAX
};

enum Enum2
{
  ENUM2_E0,
  ENUM2_E1,
  LAST_ENUM1_ENUMERATOR
};

void
fun0(enum Enum0 p __attribute__((unused)))
{
}

void
fun1(enum Enum1 p __attribute__((unused)))
{
}

void
fun2(enum Enum2 p __attribute__((unused)))
{
}
