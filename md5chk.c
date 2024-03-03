/*
 * Create shell readable MD5 lists.
 * 
 * find . -type f -print0 |
 * md5chk -n |
 * while read -r md5 name
 * do
 *	eval name="\$'$name'"
 *	...
 * done
 *
 * This Works is placed under the terms of the Copyright Less License,
 * see file COPYRIGHT.CLL.  USE AT OWN RISK, ABSOLUTELY NO WARRANTY.
 */

#define TINO_NEED_OLD_ERR_FN

#include "tino/buf_line.h"
#include "tino/getopt.h"
#include "tino/md5.h"

#include <inttypes.h>

#include "md5chk_version.h"

static unsigned char	tchar;
static int		nflag, unbuffered, quiet, stdinflag, direct, zero;
static int		ignore, errs;
static int		overlap;
static const char	*prefix;
static unsigned long long	maxsize;
static unsigned long long	offset, exact;
static int		cat;

static FILE		*out;

static tino_md5_ctx	ctx[3];
static int		effort;	/* additional contexts calculated: 0-2	*/

static unsigned blocksize;
static char *block;
static unsigned blocknumber;
static int	blocknumbers;

static int
md5err(const char *s, ...)
{
  tino_va_list  list;

  tino_va_start(list, s);
  tino_verr(&list);
  tino_va_end(list);

  return 1;
}

static void
md5init(int i)
{
  tino_md5_init(ctx+i);
  if (blocknumber)
    {
      char tmp[22];

      if (!i && blocknumbers == 2)
        blocknumber	= 1;
      snprintf(tmp, sizeof tmp, "%020u", blocknumber);
      tino_md5_update(ctx+i, tmp, 20);
      if (!++blocknumber)
        blocknumber++;
    }
  if (prefix)
    tino_md5_update(ctx+i, prefix, strlen(prefix));
}

static void
md5upd(const void *ptr, size_t len)
{
  int	i;

  for (i=effort; i>=0; i--)
    tino_md5_update(ctx+i, ptr, len);
  if (cat)
    {
      fwrite(ptr, 1, len, stdout);
      if (unbuffered)
        fflush(stdout);
    }
}

static void
md5exit(int n)
{
  unsigned char	digest[16];
  int i;

  tino_md5_final(ctx+n, digest);
  for (i=0; i<16; i++)
    fprintf(out, "%02x", digest[i]);
  if (unbuffered)
    fflush(out);
}

static void
md5copy(int from, int to)
{
  memcpy(ctx+to, ctx+from, sizeof *ctx);
}

static int
read_away(int fd, unsigned long long count, const char *name)
{
  char	buf[BUFSIZ];

  while (count)
    {
      size_t	max;
      int	got;

      max	= sizeof buf;
      if (max>count)
        max	= count;
      if ((got = tino_file_readE(fd, buf, max)) == 0)
        return md5err("unexpected EOF: %s", name);
      if (got < 0)
        return md5err("read error: %s", name);
      count -= max;
    }
  return 0;
}

/* returns true if another block must be read	*/
static unsigned long long
md5read(int fd, unsigned long long count, const char *name, int *err)
{
  int			got;
  unsigned		blk;
  unsigned long long	len;
  unsigned long long	cnt;
  int			init;

  len = maxsize;
  if (!len || (count && len>count))
    len	= count;

  /* blocksize and maxsize are constant.
   * count is maximized on the first invocation.
   * Hence blk is the maximum ever needed on the first invocation.
   */
  blk = blocksize;
  if (len && blk>len)
    blk = len;
  if (!block)
    block	= tino_allocO(blk);	/* blk is allocated on the first invocation	*/

  got = 0;
  cnt = 0;
  for (init=effort; blk && (got=tino_file_readE(fd, block, (size_t)blk))>0; init=0)
    {
      if (init)	/* hack to recreate original behavior	*/
        {
          md5init(1);
          init	 = 0;
        }
      md5upd(block, got);
      cnt += got;
      if (!len)
        continue;
      len -= got;
      if (blk>len)
        blk = len;
    }
  if (got<0)
    {
      *err	= 1;	/* read error	*/
      return 0;
    }
  if (!got && count)
    *err	= 2;	/* unexpected EOF: short read on -e	*/
  return cnt;
}

static int
md5str(const char *str)
{
  size_t	len;

  len	= strlen(str);
  if (offset)
    {
      if (len < offset)
        return md5err("string given is too short for -f");
      str += offset;
      len -= offset;
    }
  if (exact)
    {
      if (len < exact)
        return md5err("string given is too short for -e");
       len	= exact;
    }
  effort = 0;
  md5init(0);
  md5upd(str, strlen(str));
  md5exit(0);
  return 0;
}

static void
shellescapename(const char *s)
{
  for (; *s; s++)
    if (((unsigned char)*s)<33 || ((unsigned char)*s)>=127)
      fprintf(out, "\\%03o", (unsigned char)*s);
    else
      switch (*s)
        {
        case '\\':
        case '\'':
          fputc('\\', out);
        default:
          fputc(*s, out);
          break;
        }
}

static void
term(void)
{
  if (zero)
    fputc(0, out);
  else
    fputc('\n', out);
  if (unbuffered)
    fflush(out);
}

static void
errterm(int type)
{
  int e;

  if (!effort)
    return;
  e = errno;
  fprintf(out, type == 2 ? "[EOF]" : "[ERR]");
  term();
  errno = e;
}

static int
md5file(const char *name)
{
  unsigned long long	cnt;
  int			fd, err, more;
  char			*end;
  unsigned long long	got;

  fd	= strtoimax(name, &end, 10);
  if (*name && fd >= 0 && fd != INTMAX_MAX && end && !*end && *name)
    {
      /* numeric value is FD to use	*/
      if (read_away(fd, offset, name))
        return 1;
    }
  else if (stdinflag && !strcmp(name, "-"))
    {
      fd	= 0;
      if (read_away(fd, offset, name))
        return 1;
    }
  else if ((fd=open(name, O_RDONLY))<0)
    return md5err("cannot open: %s", name)|1;
  else if (offset)
    {
      if ((unsigned long long)lseek(fd, (off_t)0, SEEK_END) < offset + exact)
        return md5err("file too short: %s", offset, name)|1;
      if ((unsigned long long)lseek(fd, (off_t)offset, SEEK_SET) != offset)
        return md5err("cannot seek to offset %llu: %s", offset, name)|1;
    }
  effort= 0;
  more	= 0;
  cnt	= exact;
  err	= 0;
  md5init(0);
  for (got=0;;)
    {
      if (cnt)
        {
          cnt -= got;
          if (!cnt)
            break;	/* artificial EOF, got != 0	*/
        }
      got = md5read(fd, cnt, name, &err);
      if (!got || err || !maxsize)	/* EOF or ERR or everything read	*/
        break;

      /* maxsize > 0: Output blocks of
       * a+b+c=e	non overlapping mode
       * a-b-c=e	overlapping mode
       */
      if (!effort)
        {
          /* first block of -m
           */
          effort = 1;
          /* copy the first block so we can output it
           */
          md5copy(0,1);	/* 0 is for =e	*/
          md5exit(1);	/* output current sum	*/
          /* md5init(1); done in md5read() now	*/
          continue;
        }

      more = 1;		/* we need the =	*/
      /* already saw output	*/
      if (!overlap)
        {
          /* append next block	*/
          fputc('+', out);
          md5exit(1);	/* output current sum	*/
          /* md5init(1); done in md5read() now	*/
          continue;
        }

      /* overlapping case	*/
      if (effort==1)
        {
          /* first 2 blocks	*/
          effort = 2;
          md5copy(0,2);	/* 0 contains sum of first and second block, output this	*/
        }

      fputc('-', out);
      md5exit(2);	/* output sum of combined last 2 blocks	*/
      md5copy(1,2);	/* preset last block into combination sum 2	*/
      /* md5init(1); done in md5read() now	*/
    }
  if (err)
    {
      errterm(err);
      md5err(err == 2 ? "unexpected EOF: %s" : "read error: %s", name);
      tino_file_closeE(fd);
      return 1;
    }
  if (tino_file_closeE(fd))
    {
      errterm(0);
      md5err("cannot close: %s", name);
      return 1;
    }
  /* when we came here we have following cases:
   * !effort:		return md5exit(0)
   * !more:		return as md5exit(1) already did the output above
   * effort == 1:	
   */
  if (effort)
    {
      if (!more)
        return 0;
      if (effort == 2)
        {
          fputc('+', out);
          md5exit(2);
        }
      fputc('=', out);
    }
  /* output complete hash	*/
  md5exit(0);
  return 0;
}

static int
md5(const char *name)
{
  if (direct ? md5str(name) : md5file(name))
    return 1;	/* error */
  if (!quiet)
    {
      fputc(' ', out);
      if (zero)
        fprintf(out, "%s", name);
      else
        shellescapename(name);
    }
  term();
  return 0;
}

static int
md5chk(void)
{
  TINO_BUF	buf;
  const char	*name;
  int		err;

  if (stdinflag)
    return md5("-");
  tino_buf_initO(&buf);
  err = 0;
  while ((name=tino_buf_line_readE(&buf, 0, tchar ? tchar : nflag ? 0 : -1))!=0)
    err |= md5(name);
  return err;
}

static void
verror_fn(const char *prefix, TINO_VA_LIST list, int err)
{
  errs	= 1;
  if (!ignore)
    tino_verror_std(prefix, list, err);
}

#if 0
const char *
shit_mode(void *ptr, const char *arg, const char *opt, void *usr)
{
  struct tino_shit	shit;
  struct tino_shit_io	*me, *r;

  tino_shit_initO(&shit, "md5chk");

  me	= tino_shit_helperO(&shit, 0, getenv("TINO_SHIT_MODE"));
  if (!me)
    return "SHIT mode cannot be used manually";

  unbuffered	= 1;
  stdinflag	= 0;

  while ((r=tino_shit_request_inN(me))!=0)
    {
      tino_shit_answer_spoolO(r);
      md5(tino_shit_stringO(r));
      tino_shit_answer_finishO(r);

      tino_shit_closeO(r);
    }
  tino_shit_exitO(&shit, 0);
  return 0;
}
#endif

int
main(int argc, char **argv)
{
  int		argn;

  tino_verror_fn	= verror_fn;
  argn	= tino_getopt(argc, argv, 0, -1,
                      TINO_GETOPT_VERSION(MD5CHK_VERSION)
                      " [args..]\n"
                      "\tnumeric falues are the FD to use, - is stdin\n"
                      "Prototype 0:\n"
                      "\tmd5chk -d 'string1' 'string2'\n"
                      "\techo test | md5chk -s\n"
                      "Prototype 1:\n"
                      "\tif md5=\"`md5chk -iq \"$name\"`\"; then ...\n"
                      "Prototype 2:\n"
                      "\tfind . -type f | ./md5chk -t10\n"
                      "Prototype 3:\n"
                      "\tfind . -type f -print0 |\n"
                      "\t%s -n |\n"
                      "\twhile read -r md5 name\n"
                      "\tdo\n"
                      "\t\teval name=\"\\$\'$name\'\"\n"
                      "\t\t...\n"
                      "\tdone"
                      ,

#if 0
                      TINO_GETOPT_IGNORE TINO_GETOPT_LLOPT TINO_GETOPT_FN
                      "shit	Shell Helper Integrated Transfer (do not use)"
                      , shit_mode,
#endif

                      TINO_GETOPT_USAGE
                      "h	this help"
                      ,

                      TINO_GETOPT_UNSIGNED
                      TINO_GETOPT_DEFAULT
                      TINO_GETOPT_SUFFIX
                      "b size	Blocksize for operation"
                      , &blocksize,
                      (unsigned)(BUFSIZ*10),

                      TINO_GETOPT_FLAG
                      "c	Cat mode, echo input to stdout again\n"
                      "		sends MD5 sum to stderr, use -u to use 2>&1"
                      , &cat,

                      TINO_GETOPT_FLAG
                      "d	Do md5sum of commandline args or lines from stdin"
                      , &direct,

                      TINO_GETOPT_ULLONG
                      TINO_GETOPT_SUFFIX
                      "e count	Read exactly count bytes, 0 is unlimited.\n"
                      "		Errors if there are less bytes"
                      , &exact,

                      TINO_GETOPT_ULLONG
                      TINO_GETOPT_SUFFIX
                      "f offset	Start reading at the given offset.  On stdin this skips.\n"
                      "		Errors if there are less bytes or seek() is impossible"
                      , &offset,

                      TINO_GETOPT_FLAG
                      "i	Ignore errors silently"
                      , &ignore,

                      TINO_GETOPT_MAX
                      TINO_GETOPT_FLAG
                      "k	prefix MD5 with blocKnumbers.  Implies -m\n"
                      "		This way equal blocks give different hashes.\n"
                      "		Use two times to reset between args/files"
                      , &blocknumbers,
                      2,

                      TINO_GETOPT_FLAG
                      "l	overLapping mode for -m (-m defaults to 1 MiB)\n"
                      "		Outputs 1-12-23-34+4=1234 (triple effort).\n"
                      "		The partial HASHes overlap by 1 block of size -m"
                      , &overlap,

                      TINO_GETOPT_ULLONG
                      TINO_GETOPT_SUFFIX
                      "m size	Max size of block for md5 (default: unlimited)\n"
                      "		One MD5 sum each size bytes (and one for all).\n"
                      "		Outputs 1+2+3+4=1234. (double effort)"
                      , &maxsize,

                      TINO_GETOPT_FLAG
                      "n	read NUL terminated lines\n"
                      "		Note that NUL always acts as line terminator."
                      , &nflag,

                      TINO_GETOPT_STRING
                      "p str	Preset md5 algorithm with given string\n"
                      "		This modifies the md5 algorithm by prefixing str."
                      , &prefix,

                      TINO_GETOPT_FLAG
                      "q	Quiet mode: do not print (shell escaped) file names"
                      , &quiet,

                      TINO_GETOPT_FLAG
                      "s	read data from Stdin instead, not a file list\n"
                      "		Enables '-' as file argument for stdin, too."
                      , &stdinflag,

                      TINO_GETOPT_CHAR
                      "t	line Termination character, default whitespace\n"
                      "		Note: -t defaults to NUL if -n present."
                      , &tchar,

                      TINO_GETOPT_FLAG
                      "u	Unbuffered output"
                      , &unbuffered,

                      TINO_GETOPT_FLAG
                      "z	Write NUL(\"zero\") terminated lines, disables shell escape"
                      , &zero,

                      NULL);

  if (argn<=0)
    return 1;

  blocknumber	= blocknumbers ? 1 : 0;
  if ((overlap || blocknumbers) && !maxsize)
    maxsize = 1024 * 1024;

  if ((unsigned long long)(off_t)exact  != exact ||
      (unsigned long long)(off_t)offset != offset)
    return md5err("Sorry, conversion of bytes to off_t failed, probably overflow");
  if (stdinflag && direct)
    return md5err("Warning: Options -d and -s together makes no sense");

  out = cat ? stderr : stdout;
  if (argn<argc)
    do
      md5(argv[argn]);
    while (++argn<argc);
  else
    md5chk();
  return errs;
}
