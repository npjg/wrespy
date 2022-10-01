## wrespy
For many years, the most cross-platform tool for extracting resources from NE/PE binaries has been wrestool. However, wrestool is very old, no longer maintained, and has several problems that make it cumbersome for computer archaeology:
 - Only bitmaps, (group) icons, and (group) cursors natively supported. All other resources must be exported raw.
 - Cannot extract 
 - Bitmaps, icons, and cursors exported from NE files have damaged headers and must be repaired before most graphics software can view them.

In my computer archaeology work, I must often extract resources from NE executables.
I tired of the gymnastics required to massage the `wrestool` output into something more portable.
Thus, I took the idea behind `wrestool` - a platform-independent way to extract resources from NE/PE binaries - and updated it to be more comprehensive and self-documenting.

The name `wrespy` is a tribute to this tool's heritage and inspiration.

Executable format independent 

This library introduces 