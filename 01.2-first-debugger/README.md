# Lab 1.2 : First Debugger
**Series:** Windows Internals
**Environment:** Windows 11 Enterprise VM · Proxmox · isolated (no internet)

---

## Whats this lab is about

In this lab, we trying to figure out what's happening when we are running a program (call Lab 1.2.exe in this lab) in Windows. This lab is about using x64dgb to try to have a better understeandingif whats is going on i run this process.

---

---

## What i built for this

Jsut a little "Hello World" C program, the objectives here is really not to start with a BIG  program where i'm just going to be lost later haha.

--------------------------------------
![Execution without admin privileges](screenshots/c_program.png)

![Execution without admin privileges](screenshots/c_program_running.png)

---

---

## First step : breakpoints

So the first step here was to find the break points where my actual code is starting : on the fourth breakpoint. My first question when i saw that was "Why my code is not starting on th eofrst breakpoint ?", we'll see why in just a moment.

--------------------------------------
![Execution without admin privileges](screenshots/first_breakpoint.png)
![Execution without admin privileges](screenshots/MessageBoxA_breakpoint.png)

---

---

## Seconds step : ntdll.dll

For this steps we can go on the "Call Stack" tab pr "Pile d'appels" in french ( as we cann see on these screenshots below). In this we see the order of execution of the process, especially the fact that ndll.dll is called in a first place. Whats is ntdll.dll ? It is a dll that windows map in yout proces smemory befor anything else : ntdll.dll is a loader, it réolves dépendancies and charges dll in the right order.
On the images below we can see that the kernel is starting th threads by calling ntdll in a firest place (Utilisantdll.Rt....), then the CRT ( C Runtime) initializes, CRT calling main funtion, then my code ( +39 bytes after the starting of main function).

--------------------------------------
![Execution without admin privileges](screenshots/call_stack.png)

---

---

## Final step (for this lab)

Update soon.

---