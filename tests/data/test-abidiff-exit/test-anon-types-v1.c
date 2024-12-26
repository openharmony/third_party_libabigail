/**
 * Compile with:
 *
 * gcc -c -g -fno-eliminate-unused-debug-types test-anon-types-v{0,1}.c
 */

union
{
  int a;
  int b;
  int c;
};

struct
{
  int a;
  int b;
  int c;
};

enum
{
  a,
  b,
  c,
  d,
  e,
  f
};

void
fun()
{}
