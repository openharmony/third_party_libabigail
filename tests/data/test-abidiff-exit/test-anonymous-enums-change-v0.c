/*
 *  Compile this with:
 *    gcc -c -g -fno-eliminate-unused-debug-types test-anonymous-enums-change-v0.c 
 */

enum
  {
    E1_0,
    E1_1,
  } v1;

enum
  {
    E3_0,
    E3_1,
  };

enum
  {
    E4_0,
    E4_1,
    E4_2,
    E4_LAST_ELEMENT
  };

enum
  {
    E0_0,
    E0_1,
  } v0;

enum
  {
    E2_0,
    E2_1,
  } v2;
