/* $Header$
 *
 * Create shell readable MD5 lists.
 * 
 * find . -type f -print0 |
 * md5chk -n |
 * while read -r md5 name
 * do
 *	eval name="\$\'$name\'"
 *	...
 * done
 *
 * Copyright (C)2006 Valentin Hilbig, webmaster@scylla-charybdis.com
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
 * Revision 1.3  2006-07-25 21:54:22  tino
 * See ChangeLog
 *
 * Revision 1.2  2006/07/25 21:31:21  tino
 * Added commandline usage (files and -q)
 *
 * Revision 1.1  2006/07/25 20:56:18  tino
 * First version
 */

#include "tino/getopt.h"
#include "tino/md5.h"
#include "tino/buf_line.h"

#include "md5chk_version.h"

static unsigned char	tchar;
static int		nflag, unbuffered, quiet;
static int		ignore, errs;

static void
md5read(FILE *fd, char digest[15])
{
  tino_MD5_CTX	ctx;
  char		data[BUFSIZ*10];
  int		got;

  tino_MD5Init(&ctx);
  while ((got=fread(data, 1, sizeof data, fd))>0)
    tino_MD5Update(&ctx, data, got);
  tino_MD5Final(digest, &ctx);
}

static void
shellescapename(const char *s)
{
  for (; *s; s++)
    if (*s<33)
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
  unsigned char	digest[15];
  int		i;
  FILE		*fd;

  if ((fd=fopen(name, "rb"))==NULL)
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
  for (i=0; i<sizeof digest; i++)
    printf("%02x", digest[i]);
  if (!quiet)
    {
      printf(" ");
      shellescapename(name);
    }
  printf("\n");
  if (unbuffered)
    fflush(stdout);
}

static void
md5chk(void)
{
  TINO_BUF	buf;
  const char	*name;

  tino_buf_init(&buf);
  while ((name=tino_buf_line_read(&buf, 0, tchar ? tchar : nflag ? 0 : -1))!=0)
    md5(name);
}

static void
verror_fn(const char *prefix, const char *s, va_list list, int err)
{
  errs	= 1;
  if (!ignore)
    tino_verror_std(prefix, s, list, err);
}

int
main(int argc, char **argv)
{
  int		argn;

  tino_verror_fn	= verror_fn;
  argn	= tino_getopt(argc, argv, 0, -1,
		      TINO_GETOPT_VERSION(MD5CHK_VERSION)
		      " [files..]",

		      TINO_GETOPT_USAGE
		      "h	this help"
		      ,

		      TINO_GETOPT_FLAG
		      "n	read NUL terminated lines (else -t default to whitespace)\n"
		      "		Note that NUL always acts as line terminator."
		      , &nflag,

		      TINO_GETOPT_CHAR
		      "t	line termination character, default whitespace\n"
		      "		Note: -t defaults to NUL if -n present."
		      , &tchar,

		      TINO_GETOPT_FLAG
		      "i	ignore errors silently"
		      , &ignore,

		      TINO_GETOPT_FLAG
		      "q	quiet mode: do not print file names"
		      , &quiet,

		      TINO_GETOPT_FLAG
		      "u	unbuffered output"
		      , &unbuffered,

		      NULL);

  if (argn<=0)
    return 1;
  
  if (argn<argc)
    do
      md5(argv[argn]);
    while (++argn<argc);
  else
    md5chk();
  return errs;
}
