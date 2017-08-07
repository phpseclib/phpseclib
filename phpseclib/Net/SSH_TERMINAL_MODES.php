<?php

namespace phpseclib\Net;

use phpseclib\Common\Enum;

class SSH_TERMINAL_MODES extends Enum
{
    const TTY_OP_END = 0; //Indicates end of options.

    const VINTR = 1; //Interrupt character; 255 if none.  Similarly
    //for the other characters.  Not all of these
    //characters are supported on all systems.

    const VQUIT = 2; //The quit character (sends SIGQUIT signal on
    //POSIX systems).

    const VERASE = 3; //Erase the character to left of the cursor.

    const VKILL = 4; //Kill the current input line.

    const VEOF = 5; //End-of-file character (sends EOF from the terminal).

    const VEOL = 6; //End-of-line character in addition to carriage return and/or linefeed.

    const VEOL2 = 7; //    Additional end-of-line character.

    const VSTART = 8; //Continues paused output (normally control-Q).

    const VSTOP = 9; //Pauses output (normally control-S).

    const VSUSP = 0; //Suspends the current program.

    const VDSUSP = 1; //Another suspend character.


    const VREPRINT = 2; //Reprints the current input line.

    const VWERASE = 3; //Erases a word left of cursor.

    const VLNEXT = 4; //Enter the next character typed literally,
    //even if it is a special character

    const VFLUSH = 5; //Character to flush output.

    const VSWTCH = 6; //Switch to a different shell layer.

    const VSTATUS = 7; //Prints system status line (load, command, pid, etc).

    const VDISCARD = 8; //Toggles the flushing of terminal output.

    const IGNPAR = 0; //The ignore parity flag.  The parameter SHOULD be 0 if this flag is FALSE, and 1 if it is TRUE.

    const PARMRK = 1; //Mark parity and framing errors.

    const INPCK = 2; //Enable checking of parity errors.

    const ISTRIP = 3; //Strip 8th bit off characters.

    const INLCR = 4; //Map NL into CR on input.

    const IGNCR = 5; //Ignore CR on input.

    const ICRNL = 6; //Map CR to NL on input.

    const IUCLC = 7; //Translate uppercase characters to lowercase.

    const IXON = 8; //Enable output flow control.

    const IXANY = 9; //Any char will restart after stop.

    const IXOFF = 0; //Enable input flow control.

    const IMAXBEL = 1; //Ring bell on input queue full.

    const ISIG = 0; //Enable signals INTR, QUIT, [D]SUSP.

    const ICANON = 1; //Canonicalize input lines.

    const XCASE = 2; //Enable input and output of uppercase characters by preceding their lowercase equivalents with "\".

    const ECHO = 3; //Enable echoing.

    const ECHOE = 4; //Visually erase chars.

    const ECHOK = 5; //Kill character discards current line.

    const ECHONL = 6; //Echo NL even if ECHO is off.

    const NOFLSH = 7; //Don't flush after interrupt.

    const TOSTOP = 8; //Stop background jobs from output.

    const IEXTEN = 9; //Enable extensions.

    const ECHOCTL = 0; //Echo control characters as ^(Char).

    const ECHOKE = 1; //Visual erase for line kill.

    const PENDIN = 2; //Retype pending input.

    const OPOST = 0; //Enable output processing.

    const OLCUC = 1; //Convert lowercase to uppercase.

    const ONLCR = 2; //Map NL to CR-NL.

    const OCRNL = 3; //Translate carriage return to newline (output). const ONOCR = 4; //Translate newline to carriage return-newline (output).

    const ONLRET = 5; //Newline performs a carriage return (output).
    //          90    CS7         7 bit mode.
    //          91    CS8         8 bit mode.

    const PARENB = 2; //Parity enable.

    const PARODD = 3; //Odd parity, else even.

    const TTY_OP_ISPEED = 8; //Specifies the input baud rate in bits per second.

    const TTY_OP_OSPEED = 9; //Specifies the output baud rate in bits per second.
}
