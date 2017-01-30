/*
 *  Measure peer latency and calculate community values
 *
 *  	https://dn42.net/howto/Bird-communities
 *
 *  gcc -g -O2 -Wall dn42-comgen.c -o dncg -lm
 *
 *  ./dncg -b 100 -e normal -f 1 172.22.0.42
 *
 */

#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define ICMP_COUNT 4

#define OF_NORMAL		0
#define OF_BIRDFILTER		1
#define OF_BIRDNATIVE		2

#define EM_NONE			"none"
#define EM_UNSAFE		"unsafe"
#define EM_NORMAL		"normal"
#define EM_PFS			"pfs"

#define USAGE_STR "Usage: %s [-b <bandwidth(mbps)>] [-e <none|unsafe|normal|pfs>] [-c <icmp count>] [-f <0|1|2>] host"

#define BASE_OPTSTRING	"f:c:e:b:"

#if _POSIX_C_SOURCE >= 2 || _XOPEN_SOURCE
#define OPTSTRING 	"-" BASE_OPTSTRING
#else
#define OPTSTRING 	BASE_OPTSTRING
#endif

static int outformat = OF_NORMAL;

#define print_usage fprintf(stderr, USAGE_STR "\n", argv[0])
#define handle_ba { print_usage; _exit (1); }
#define check_anull if ( optarg == NULL ) handle_ba

typedef struct encryption_mode
{
  char *mode;
  int code;
} emode;

const static emode emodes[] =
  {
    { .mode = EM_NONE, .code = 31 },
    { .mode = EM_UNSAFE, .code = 32 },
    { .mode = EM_NORMAL, .code = 33 },
    { .mode = EM_PFS, .code = 34 } };

#define EM_COUNT sizeof(emodes) / sizeof(emode)

static double bw = 100;
static char *sec = EM_NORMAL;
static char *neigh = NULL;
static int icmp_count = ICMP_COUNT;

static int
isinpath (const char *path, int amode)
{
  int r = 1;
  char *dup = strdup (getenv ("PATH")), *s = dup, *p = NULL;
  char *b = malloc (PATH_MAX);

  do
    {
      p = strchr (s, ':');
      if (p != NULL)
	p[0] = 0;

      snprintf (b, PATH_MAX, "%s/%s", s, path);
      if (0 == access (b, amode))
	{
	  r = 0;
	  break;
	}

      s = p + 1;
    }
  while (p != NULL);

  free (b);
  free (dup);

  return r;
}

static float
get_latency (const char *host)
{
  char *buf = malloc (512);
  size_t cmdlen = strlen (host) + 32;
  char *cmd = malloc (cmdlen + 1);

  char *bin;
  char *proto;

  if (strchr (host, ':'))
    {
      if (!isinpath ("ping6", R_OK | X_OK))
	{
	  bin = "ping6";
	  proto = "";
	}
      else
	{
	  bin = "ping";
	  proto = "-6";
	}
    }
  else
    {
      bin = "ping";
      proto = "";
    }

  snprintf (cmd, cmdlen, "%s %s -n -c %d %s", bin, proto, icmp_count, host);

  FILE *ph;
  float result;

  if ((ph = popen (cmd, "r")) == NULL)
    {
      fprintf (stderr, "unable to run ping: %s", strerror (errno));
      result = -1.0;
      goto cleanup;
    }

  char *tof;
  result = 0.0;
  int ok = 0;

  while (fgets (buf, 512, ph))
    {
      tof = strstr (buf, "time=");
      if (tof)
	{
	  errno = 0;
	  result += strtof (tof + 5, NULL);
	  if (!(errno == EINVAL || errno == ERANGE))
	    ok = 1;
	}
    }

  if (!ok)
    result = -1.0;
  else
    result /= (float) icmp_count;

  pclose (ph);

  cleanup: ;

  free (cmd);
  free (buf);

  return result;
}

static int
parse_opts (int argc, char **argv)
{
  int opt;
  while ((opt = getopt (argc, argv, OPTSTRING)) != -1)
    {
      switch (opt)
	{
	case 'b':
	  check_anull
	  bw = strtod (optarg, NULL);
	  if ( errno == EINVAL)
	    {
	      fprintf (stderr, "invalid bandwith option\n");
	      return 1;
	    }
	  if (bw <= (double) 0 || errno == ERANGE)
	    {
	      fprintf (stderr, "bandwidth value out of range\n");
	      return 1;
	    }
	  break;
	case 'e':
	  check_anull
	  sec = optarg;
	  break;
	case 'c':
	  check_anull
	  icmp_count = atoi (optarg);
	  if (icmp_count <= 0)
	    icmp_count = ICMP_COUNT;
	  break;
	case 'f':
	  check_anull
	  outformat = atoi (optarg);
	  break;
	case 1:
	  neigh = optarg;
	  break;
	default:
	  handle_ba
	}
    }

  if (neigh == NULL)
    if (optind < argc)
      neigh = argv[optind];

  return 0;
}

static int
find_sm_code (char *mode)
{
  int i = EM_COUNT;

  while (i--)
    {
      if (!strcmp (emodes[i].mode, sec))
	return emodes[i].code;
    }

  return -1;
}

int
main (int argc, char *argv[])
{
  if (argc == 1)
    handle_ba

  parse_opts (argc, argv);

  if (neigh == NULL || !strlen (neigh))
    {
      fprintf (stderr, "missing host address\n");
      handle_ba
    }

  int com_security;

  if ((com_security = find_sm_code (sec)) == -1)
    {
      fprintf (stderr, "invalid encryption specifier: %s\n", sec);
      handle_ba
    }

  float latency = get_latency (neigh);

  if (latency == -1.0)
    {
      fprintf (stderr, "icmp failed: %s\n", neigh);
      if (outformat == OF_BIRDFILTER)
	_exit (1);
    }

  fprintf (
      stderr,
      "# neighbor: %s, latency: %.3f ms, bandwidth: %.1f mbps, security: %s\n",
      neigh, latency, bw, sec);

  int com_bandwidth = bw < 1.0 ? 21 : 20 + (int) log10 (bw) + 2;

  if (com_bandwidth > 29)
    com_bandwidth = 29;

  int com_latency = (int) ceil (logf (latency <= (float) 1 ? 1.1 : latency));

  if (com_latency > 9)
    com_latency = 9;

  switch (outformat)
    {
    case OF_BIRDFILTER:
      printf ("import where dn42_import_filter(%d,%d,%d);\n"
	      "export where dn42_export_filter(%d,%d,%d);\n",
	      com_latency, com_bandwidth, com_security, com_latency,
	      com_bandwidth, com_security);
      break;
    case OF_BIRDNATIVE:
      if (latency != -1.0)
	printf ("link latency %d;\n", com_latency);

      printf ("link bandwidth %d;\n"
	      "link security %d;\n",
	      com_bandwidth, com_security);
      break;
    default:
      printf ("%s %d %d %d\n", neigh, latency == -1.0 ? -1 : com_latency,
	      com_bandwidth, com_security);
    }

  exit (0);
}

