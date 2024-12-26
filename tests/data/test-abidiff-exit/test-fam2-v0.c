struct foo
{
  int member0;
  char pad[10];
};

void
foo(struct foo * p __attribute__((unused)))
{
}
