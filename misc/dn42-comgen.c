/*
 *  Measure peer latency and calculate community values
 *
 *  	https://dn42.net/howto/Bird-communities
 *
 *  gcc -g -O2 -Wall dn42-comgen.c -o dncg -lm
 *
 *  ./dncg -b100 -e normal -f1 172.22.0.42
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
#define PATH_MAX 		4096
#endif

#define ICMP_COUNT 		4

#define OF_NORMAL		0
#define OF_BIRDFILTER		1
#define OF_BIRDNATIVE		2

#define EM_NONE			"none"
#define EM_UNSAFE		"unsafe"
#define EM_NORMAL		"normal"
#define EM_PFS			"pfs"

#define USAGE_STR 		"Usage: dncg [-64v] [-b <bandwidth(mbps)>] [-e <none|unsafe|normal|pfs>] [-c <icmp count>] [-f <0|1|2>] host"

#define BASE_OPTSTRING		"f:c:e:b:64v"

#if _POSIX_C_SOURCE >= 2 || _XOPEN_SOURCE
#define OPTSTRING 		"-" BASE_OPTSTRING
#else
#define OPTSTRING 		BASE_OPTSTRING
#endif

static int outformat = OF_NORMAL;

#define print_usage fprintf(stderr, USAGE_STR "\n")
#define handle_ba { print_usage; _exit (1); }
#define ba_perror(m,...) { fprintf(stderr, m "\n", ##__VA_ARGS__); handle_ba }

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

static double bw = 0.0;
static char *sec = NULL;
static char *neigh = NULL;
static int icmp_count = ICMP_COUNT;
static int icmpv = 0;

static int verbose = 0;

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
get_latency (const char *host, int icmpv)
{
  char *buf = malloc (512);
  size_t cmdlen = strlen (host) + 32;
  char *cmd = malloc (cmdlen + 1);

  char *bin;
  char *proto;

  if (strchr (host, ':') || icmpv == 6)
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
      if (icmpv == 4)
	proto = "-4";
      else
	proto = "";
    }

  snprintf (cmd, cmdlen, "%s %s -n -c %d %s", bin, proto, icmp_count, host);

  FILE *ph;
  float result;

  if ((ph = popen (cmd, "r")) == NULL)
    {
      fprintf (stderr, "unable to run %s: %s", bin, strerror (errno));
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
	  if (verbose)
	    fputs (buf, stderr);

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
	  bw = strtod (optarg, NULL);
	  if ( errno == EINVAL)
	    {
	      ba_perror("invalid bandwith option");
	    }
	  if (errno == ERANGE)
	    {
	      ba_perror("bandwidth value out of range");
	    }
	  break;
	case 'e':
	  sec = optarg;
	  break;
	case 'c':
	  icmp_count = atoi (optarg);
	  if (icmp_count <= 0)
	    icmp_count = ICMP_COUNT;
	  break;
	case 'f':
	  outformat = atoi (optarg);
	  break;
	case '6':
	  icmpv = 6;
	  break;
	case '4':
	  icmpv = 4;
	  break;
	case 'v':
	  verbose = 1;
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
      if (!strcmp (emodes[i].mode, mode))
	return emodes[i].code;
    }

  return -1;
}

static void
check_options (void)
{
  if (bw <= (double) 0)
    {
      ba_perror("missing or invalid bandwidth option");
    }

  if (sec == NULL)
    {
      ba_perror("missing encryption option");
    }

  if (neigh == NULL || !strlen (neigh))
    {
      ba_perror("missing host address");
    }
}

static int
calc_security (char *sv)
{
  int com_security;

  if ((com_security = find_sm_code (sv)) == -1)
    {
      ba_perror("invalid encryption specifier: %s", sv);
    }

  return com_security;
}

static int
calc_bandwidth (double bw)
{
  int com_bandwidth = bw < 1.0 ? 21 : 20 + (int) log10 (bw) + 2;

  if (com_bandwidth > 29)
    com_bandwidth = 29;

  return com_bandwidth;
}

static int
calc_latency (float latency)
{
  int com_latency = (int) ceil (logf (latency <= (float) 1 ? 1.1 : latency));

  if (com_latency > 9)
    com_latency = 9;

  return com_latency;
}

static void
spew (float latency, int com_latency, int com_bandwidth, int com_security)
{
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
}

int
main (int argc, char *argv[])
{
  if (argc == 1)
    handle_ba

  parse_opts (argc, argv);
  check_options ();

  int com_security = calc_security (sec);

  float latency = get_latency (neigh, icmpv);

  if (latency == -1.0)
    {
      fprintf (stderr, "icmp failed: %s\n", neigh);
      if (outformat == OF_BIRDFILTER)
	_exit (1);
    }

  fprintf (
      stderr,
      "# neighbor: %s, average rtt: %.3f ms, bandwidth: %.1f mbps, security: %s\n",
      neigh, latency, bw, sec);

  int com_latency = calc_latency (latency);
  int com_bandwidth = calc_bandwidth (bw);

  spew (latency, com_latency, com_bandwidth, com_security);

  exit (0);
}

