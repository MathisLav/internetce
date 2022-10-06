# Resources

This folder provides the version of USBDRVCE I used to build InternetCE. This note aims at explaining you how to use and install all of this.

## What is USBDRVCE?

Briefly, USBDRVCE is a library that allows C programs to access to the internet. Unfortunately, this lib is still under development, and consequently not included in the releases of the toolchain.  
So we're going to have to install it in our toolchain by ourselves. Be assured though, USBDRVCE is stable enough to be used in projects (I never had any issue about it).

## How to install it?

This can't be simpler :
 * Put `usbdrvce.h` in the include folder of your toolchain (frequently `CEdev/include`).
 * Put `usbdrvce.lib` in the `lib/libload` folder of your toolchain.
 * Install the common Lib C on your calculator. The v10.2 ([that can be downloaded here](https://github.com/CE-Programming/libraries/releases/tag/v10.2)) is recommended.
 * Transfer `usbdrvce.8xv` on you calc.
 
That's it! EZ, nah?
