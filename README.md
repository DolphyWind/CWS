# C With Semicolons
A fork of TCC that implements a new language I call "C With Semicolons" (or CWS for short) where you have to put semicolons after `if(...)`, `while(...)`, `for(...)` and `switch(...)`.
I tested this on a x86-64 machine and it works. It would probably break on another architecture. But it works on my machine™ so that's enough for me. Feel free to open up a PR if you want.

The compiler also exports `C_WITH_SEMICOLONS` macro by default, so you can write a code that supports both CWS and C at the same time.

# Example
```c
#include <stdio.h>

int main()
{
  int a, b;
  printf("First number: ");
  scanf("%d", &a);
  printf("Second number: ");
  scanf("%d", &b);

  if(a > b); // <--- CWS extension
  {
    printf("%d is greater than %d\n", a, b);
  }
  else if(a == b); // <--- Here's another
  {
    printf("Both numbers are equal\n");
  }
  else
  {
    printf("%d is less than %d", a, b);
  }

  return 0;
}
```

# Why?
This project exists solely to show to my teacher that language syntax is completely arbitrary, and it is not a good idea to derive meanings from it. That's all.
