/**
 * Compile with:
 *
 * gcc -c -g -fno-eliminate-unused-debug-types test-anon-types-v{0,1}.c
 */

union
{
  int a;
  int b;
  int d;
};

struct
{
  int a;
  int b;
};

enum
{
  a,
  b,
  c,
  d
};

union
{
  char x;
  unsigned y;
};

struct
{
  char z;
  int w;
};

void
fun()
{}
