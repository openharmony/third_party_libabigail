struct foo
{
  int member0;
  char member1;	     /*  This is an added data member.  */
  char pad[10]; 	     /*  This is not a fam, so the change should not be
				 suppressed.  */
};

void
foo(struct foo * p __attribute__((unused)))
{
}
