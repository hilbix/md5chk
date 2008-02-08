/* $Header$
 *
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
 * Copyright (C)2006-2008 Valentin Hilbig <webmaster@scylla-charybdis.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Log$
 * Revision 1.8  2008-02-08 02:38:04  tino
 * Help options sorted
 *
 * Revision 1.7  2008-02-07 01:55:23  tino
 * Option -z and minor bugfix
 *
 * Revision 1.6  2007-01-17 01:19:12  tino
 * Options -s and -d
 *
 * Revision 1.5  2006/08/01 00:18:27  tino
 * The MD5 digest was printed 1 byte too short, WHOOPS.
 *
 * Revision 1.4  2006/07/31 21:24:06  tino
 * Documentation clarified (was buggy) and help (-h) improved
 *
 * Revision 1.2  2006/07/25 21:31:21  tino
 * Added commandline usage (files and -q)
 */

#define TINO_NEED_OLD_ERR_FN

#include "tino/buf_line.h"
#include "tino/getopt.h"
#include "tino/md5.h"

#include "md5chk_version.h"

static unsigned char	tchar;
static int		nflag, unbuffered, quiet, stdinflag, direct, zero;
static int		ignore, errs;

static void
md5read(FILE *fd, unsigned char digest[16])
{
  tino_md5_ctx	ctx;
  char		data[BUFSIZ*10];
  int		got;

  tino_md5_init(&ctx);
  while ((got=fread(data, 1, sizeof data, fd))>0)
    tino_md5_update(&ctx, data, got);
  tino_md5_final(&ctx, digest);
}

static void
shellescapename(const char *s)
{
  for (; *s; s++)
    if (((signed char)*s)<33)
      printf("\\%03o", (unsigned char)*s);
    else
      switch (*s)
	{
	case '\\':
	case '\'':
	  putchar('\\');
	default:
	  putchar(*s);
	  break;
	}
}

static void
md5(const char *name)
{
  unsigned char	digest[16];
  int		i;
  FILE		*fd;

  if (direct)
    tino_md5_bin(name, strlen(name), digest);
  else
    {
      if (stdinflag && !strcmp(name, "-"))
	fd	= stdin;
      else if ((fd=fopen(name, "rb"))==NULL)
	{
	  tino_err("cannot open: %s", name);
	  return;
	}
      md5read(fd, digest);
      if (ferror(fd))
	{
	  tino_err("read error: %s", name);
	  fclose(fd);
	  return;
	}
      if (fclose(fd))
	{
	  tino_err("cannot close: %s", name);
	  return;
	}
    }
  for (i=0; i<sizeof digest; i++)
    printf("%02x", digest[i]);
  if (!quiet)
    {
      printf(" ");
      if (zero)
	printf("%s", name);
      else
	shellescapename(name);
    }
  if (zero)
    putchar(0);
  else
    putchar('\n');
  if (unbuffered)
    fflush(stdout);
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
  while ((name=tino_buf_line_read(&buf, 0, tchar ? tchar : nflag ? 0 : -1))!=0)
    md5(name);
}

static void
verror_fn(const char *prefix, TINO_VA_LIST list, int err)
{
  errs	= 1;
  if (!ignore)
    tino_verror_std(prefix, list, err);
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

		      TINO_GETOPT_USAGE
		      "h	this help"
		      ,

		      TINO_GETOPT_FLAG
		      "d	Do md5sum of commandline args or lines from stdin"
		      , &direct,

		      TINO_GETOPT_FLAG
		      "i	ignore errors silently"
		      , &ignore,

		      TINO_GETOPT_FLAG
		      "n	read NUL terminated lines\n"
		      "		Note that NUL always acts as line terminator."
		      , &nflag,

		      TINO_GETOPT_FLAG
		      "q	quiet mode: do not print (shell escaped) file names"
		      , &quiet,

		      TINO_GETOPT_FLAG
		      "s	read data from stdin instead, not a file list\n"
		      "		Enables '-' as file argument for stdin, too."
		      , &stdinflag,

		      TINO_GETOPT_CHAR
		      "t	line termination character, default whitespace\n"
		      "		Note: -t defaults to NUL if -n present."
		      , &tchar,

		      TINO_GETOPT_FLAG
		      "u	unbuffered output"
		      , &unbuffered,

		      TINO_GETOPT_FLAG
		      "z	write NUL(\"zero\") terminated lines, disables shell escape"
		      , &zero,

		      NULL);

  if (argn<=0)
    return 1;
  if (stdinflag && direct)
    {
      tino_err("Warning: Options -d and -s together makes no sense");
      return 1;
    }
  if (argn<argc)
    do
      md5(argv[argn]);
    while (++argn<argc);
  else
    md5chk();
  return errs;
}
