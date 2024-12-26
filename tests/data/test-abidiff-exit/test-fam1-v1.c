struct foo
{
  int member0;
  char member1;
  char pad[];
};

void
foo(struct foo * p __attribute__((unused)))
{
}
