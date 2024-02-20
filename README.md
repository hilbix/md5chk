See file [DESCRIPTION](DESCRIPTION) for now.

# Usage

	git clone --recursive https://github.com/hilbix/md5chk.git
	cd md5chk
	make
	sudo make install

# FAQ

WTF why?

- Because I need it

MD5 is insecure!

- MD5 is broken as security algorithm.  But it still is a good file hash and better than a CRC.
- Compare: SHA1 is broken, too.  But `git` still uses it.
- The security of an algorithm has to do with how it is used, not with the algorithm itself.
- Just be aware that there can be MD5 collisions.  To thwart a bit you can use a random `-p`.
- Even that `md5` is not cryptographical safe it still can detect file corruption due to failing hardware.
- I believe that there are no byte sequences `A` and `B` where `md5(XA)===md5(XB)` for any given `X`.
  - But I am not sure.  But I am pretty sure that `md5(X P(A)) !== md5(X P(B))` with a certain part `P(_)`.
  - So using `-b` or `-p` with a random `-e` and `-f` should even detect carefully created colliding files.

License?

- This Works is placed under the terms of the Copyright Less License,  
  see file COPYRIGHT.CLL.  USE AT OWN RISK, ABSOLUTELY NO WARRANTY.
- But be aware that some, but not all, files in Submodule `tino/`
  are not CLLed yet, so they are still under GNU GPL v2.  
  This probably will slowly change from GPLv2 to CLL,
  but this transition is not done yet.  Sorry.

