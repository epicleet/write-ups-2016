# Pwn2Win CTF 2016: Auswählen

**Category:** Reverse
**Points:** 120
**Solves:** 1
**Description:**

> The Club conducts a rigid and cruel training with their future agents.
> An exam is applied in which the student needs to stay awaken and
> concentrated during 72h looking to a computer screen. Everytime an
> asterisk appears in the screen, he needs to press the RETURN key
> within one second. The student doesn’t know if he was able to comply
> with the reaction time required by the exam until the end of those 72h,
> increasing his anxiety and psychological pressure level. Elapsed
> the 72h, the student receives an approval flag if he succeeded.
> Otherwise, all of its vital life is absorbed by the Club leaders,
> producing an slow and painful death.


## Write-up

Looking at the strings contained inside the binary, it is easy to identify that it was written in Haskell and compiled using GHC 7.10.3.

Trying to disassemble the file is a nightmare due to the lack of appropriate tooling for Haskell reverse engineering. GHC generated code adopts calling convention and stack usage patterns which are very different from the usual, and lazy evaluation introduces lots of hard-to-follow indirections.

However, as we already know what the program is supposed to do, we can restrict our analysis to how it interacts with the operating system and how we can patch this interaction in order to change its behavior appropriately.

Using `ltrace` and reading the [GHC event manager](http://hackage.haskell.org/package/base-4.8.2.0/docs/src/GHC.Event.TimerManager.html) implementation source code can help understanding how the program manages I/O and accounts for time.

```
$ ltrace ./Auswahlen
[...]
clock_gettime(1, 0x7ffe500762d0, 1, -112)     = 0
select(1, 0x7ffe50076320, 0x7ffe500763a0, 0)
```

Further analysis of `select` and `clock_gettime` usage (inspected by GDB or by a specially crafted `LD_PRELOAD` library) shows that delays between starcrosses are achieved by means of the `timeout` argument passed to `select`. After that, `clock_gettime` needs to return an acceptable time (less than one second after starcross) in order for the flag to be decoded correctly.

Finally, we implement [timemachine.c](timemachine.c), a `LD_PRELOAD` library to override these functions, defying the time accounting and also producing automatic echo to the starcrosses.

```
$ make
cc -std=gnu99 -O2 -Wall -fPIC     -c -o timemachine.o timemachine.c
cc  -fPIC -shared  timemachine.o -o timemachine.so
LD_PRELOAD=./timemachine.so ./Auswahlen
*
[...]
*
CTF-BR{GNDYd8ySt3_congrats_7qA7TuWBlK}
```


## Other write-ups and resources

* [Challenge source code](https://github.com/epicleet/binrev-2016/tree/master/Auswahlen)
