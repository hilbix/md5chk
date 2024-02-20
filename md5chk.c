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


static void
md5init(int i)
{
  tino_md5_init(ctx+i);
  if (blocknumber)
    {
      char tmp[22];

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

/* A desparate EOF checker.
 * Looks 1 character ahead.
 */
static int
fd_at_eof(FILE *fd)
{
  int	c;

  c = fgetc(fd);
  if (c==EOF)
    return 1;
  ungetc(c, fd);
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
  while (blk && (got=tino_file_readE(fd, block, (size_t)blk))>0)
    {
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

static void
md5str(const char *str)
{
  size_t	len;

  len	= strlen(str);
  if (offset)
    {
      if (len < offset)
        return (void)tino_err("string given is too short for -f");
      str += offset;
      len -= offset;
    }
  if (exact)
    {
      if (len < exact)
        return (void)tino_err("string given is too short for -e");
       len	= exact;
    }
  effort = 0;
  md5init(0);
  md5upd(str, strlen(str));
  md5exit(0);
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

static void
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
    }
  else if (stdinflag && !strcmp(name, "-"))
    {
      fd	= 0;
      if (exact)
        return (void)tino_err("seeking stdin not yet implemented: %s", name);
    }
  else if ((fd=open(name, O_RDONLY))<0)
    return (void) tino_err("cannot open: %s", name);
  else if (offset)
    {
      if ((unsigned long long)lseek(fd, (off_t)0, SEEK_END) < offset + exact)
        return (void)tino_err("file too short: %s", offset, name);
      if ((unsigned long long)lseek(fd, (off_t)offset, SEEK_SET) != offset)
        return (void)tino_err("cannot seek to offset %llu: %s", offset, name);
    }
  effort= 0;
  more	= 0;
  cnt	= exact;
  err	= 0;
#if 0
  if (blocknumber)
    blocknumber = 1;
#endif
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
          md5init(1);	/* next sum is in 1	*/
          continue;
        }

      more = 1;		/* we need the =	*/
      /* already saw output	*/
      if (!overlap)
        {
          /* append next block	*/
          fputc('+', out);
          md5exit(1);	/* output current sum	*/
          md5init(1);	/* next sum is in 1	*/
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
      md5init(1);	/* sum next block in 1	*/
    }
  if (err)
    {
      errterm(err);
      tino_err(err == 2 ? "unexpected EOF: %s" : "read error: %s", name);
      tino_file_closeE(fd);
      return;
    }
  if (tino_file_closeE(fd))
    {
      errterm(0);
      tino_err("cannot close: %s", name);
      return;
    }
  /* when we came here we have following cases:
   * !effort:		return md5exit(0)
   * !more:		return as md5exit(1) already did the output above
   * effort == 1:	
   */
  if (effort)
    {
      if (!more)
        return;
      if (effort == 2)
        {
          fputc('+', out);
          md5exit(2);
        }
      fputc('=', out);
    }
  /* output complete hash	*/
  md5exit(0);
}

static void
md5(const char *name)
{
  if (direct)
    md5str(name);
  else
    md5file(name);
  if (!quiet)
    {
      fputc(' ', out);
      if (zero)
        fprintf(out, "%s", name);
      else
        shellescapename(name);
    }
  term();
}

static void
md5chk(void)
{
  TINO_BUF	buf;
  const char	*name;

  if (stdinflag)
    {
      md5("-");
      return;
    }
  tino_buf_initO(&buf);
  while ((name=tino_buf_line_readE(&buf, 0, tchar ? tchar : nflag ? 0 : -1))!=0)
    md5(name);
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

                      TINO_GETOPT_FLAG
                      "k	prefix MD5 with blocKnumbers.  Implies -m\n"
                      "		This way equal blocks give different hashes."
                      , &blocknumber,

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

  if ((overlap || blocknumber) && !maxsize)
    maxsize = 1024 * 1024;

  if ((unsigned long long)(off_t)exact  != exact ||
      (unsigned long long)(off_t)offset != offset)
    {
      tino_err("Sorry, conversion of bytes to off_t failed, probably overflow");
      return 1;
    }
  if (stdinflag && direct)
    {
      tino_err("Warning: Options -d and -s together makes no sense");
      return 1;
    }
  out = cat ? stderr : stdout;
  if (argn<argc)
    do
      md5(argv[argn]);
    while (++argn<argc);
  else
    md5chk();
  return errs;
}
