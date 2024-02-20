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
#include "tino/shit.h"

#include "md5chk_version.h"

static unsigned char	tchar;
static int		nflag, unbuffered, quiet, stdinflag, direct, zero;
static int		ignore, errs;
static int		overlap;
static const char	*prefix;
static unsigned long long	maxsize;
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
static int
md5read(FILE *fd)
{
  int			got;
  unsigned		blk;
  unsigned long long	len;

  len = maxsize;
  blk = blocksize;
  if (len && blk>len)
    blk = len;
  if (!block)
    block	= tino_allocO(blk);
  while (blk && (got=fread(block, (size_t)1, (size_t)blk, fd))>0)
    {
      md5upd(block, got);
      if (!maxsize)
        continue;
      len -= got;
      if (blk>len)
        blk = len;
    }
  if (blk)
    return 0;	/* EOF	*/
  return !fd_at_eof(fd);
}

static void
md5str(const char *str)
{
  effort = 0;
  if (blocknumber)
    blocknumber = 1;
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
errterm(void)
{
  int e;

  if (!effort)
    return;
  e = errno;
  fprintf(out, "[ERR]");
  term();
  errno = e;
}


static void
md5(const char *name)
{
  FILE	*fd;

  if (direct)
    md5str(name);
  else
    {
      if (stdinflag && !strcmp(name, "-"))
        fd	= stdin;
      else if ((fd=fopen(name, "rb"))==NULL)
        {
          tino_err("cannot open: %s", name);
          return;
        }
      effort = 0;
      md5init(0);
      while (md5read(fd))
        {
          if (!effort)
            {
              /* first block of -m
               */
              effort = 1;
              /* copy the first block so we can output it
               */
              md5copy(0,1);
              md5exit(1);
              md5init(1);
              continue;
            }

          /* already saw output	*/
          if (!overlap)
            {
              /* append next block	*/
              fputc('+', out);
              md5exit(1);
              md5init(1);
              continue;
            }

          /* overlapping case	*/
          if (effort==1)
            {
              /* first 2 blocks	*/
              effort = 2;
              md5copy(0,2);
            }

          fputc('-', out);
          md5exit(2);
          md5copy(1,2);
          md5init(1);
          continue;
        }
      if (ferror(fd))
        {
          errterm();
          tino_err("read error: %s", name);
          fclose(fd);
          return;
        }
      if (fclose(fd))
        {
          errterm();
          tino_err("cannot close: %s", name);
          return;
        }
      if (effort)
        {
          /* already saw output	*/
          if (effort==2)
            {
              fputc('-', out);
              md5exit(2);
            }
          /* special degraded case is handled correctly, too:
           * 12 => 1+2=12 ("+2=" is output next)
           */
          fputc('+', out);
          md5exit(1);
          fputc('=', out);
        }
      /* output complete hash	*/
      md5exit(0);
    }
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

int
main(int argc, char **argv)
{
  int		argn;

  tino_verror_fn	= verror_fn;
  argn	= tino_getopt(argc, argv, 0, -1,
                      TINO_GETOPT_VERSION(MD5CHK_VERSION)
                      " [files..]\n"
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

                      TINO_GETOPT_IGNORE TINO_GETOPT_LLOPT TINO_GETOPT_FN
                      "shit	Shell Helper Integrated Transfer (do not use)"
                      , shit_mode,

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
