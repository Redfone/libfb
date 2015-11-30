#include <libfb/fb_lib.h>

#if defined(STDC_HEADERS) || defined(HAVE_STDLIB_H)
# include <stdlib.h>
#endif

#if HAVE_NET_IF_H
# include <net/if.h>
#endif

#ifndef IFNAMSIZ		/* for platforms without IFNAMSIZ? */
# define IFNAMSIZ 16            /**< default maximum length of a network interface */
#endif

#if __linux__			/* GNU GCC doesn't capitalize it? */
# define __LINUX__
#endif

/** @file get_local_mac.c
 *
 * @author Brett Carrington
 *
 * @brief Operating System specific file to find the MAC address of a local Ethernet interface
 */

/** @brief Find the MAC address of a local Ethernet interface
 * @param nicname the name of an Ethernet interface in Linux. It is
 * expected to point to be a string at least IFNAMSIZ long
 * @return pointer to 6 byte MAC address or NULL if not found
 */
u_int8_t *
get_local_mac (char *nicname)
#ifdef __LINUX__
{
  struct ifreq *ifr;
  unsigned char *mac;
  int tmp_socket;

  /* We don't actually use the socket, except for an ioctl to find the
   * MAC address.
   */
  if ((tmp_socket = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
    {
      perror ("socket");
      return NULL;
    }

  mac = malloc (6);
  if (mac == NULL)
    {
      perror ("malloc");
      return NULL;
    }

  /* Here we create an ifreq to determine the interface's MAC address
   * via the name the user supplies in `nicname'
   */

  ifr = malloc (sizeof (struct ifreq));
  if (ifr == NULL)
    {
      perror ("malloc");
      free (mac);
      return NULL;
    }
  memset (ifr, 0, sizeof (struct ifreq));

  strncpy (ifr->ifr_name, (char *) nicname, IFNAMSIZ);

  ifr->ifr_ifindex = if_nametoindex ((char *) nicname);

  if (ioctl (tmp_socket, SIOCGIFHWADDR, ifr) < 0)
    {
      perror ("SIOCGIFHWADDR");
      goto error_out;
    }

  memcpy (mac, ifr->ifr_hwaddr.sa_data, 6);
  free (ifr);
  return mac;

error_out:
  close (tmp_socket);
  free (ifr);
  free (mac);
  return NULL;
}
#else
{
  return NULL;
}
#endif
