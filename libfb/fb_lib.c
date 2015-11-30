#include <libfb/fb_lib.h>
#include <libfb/fblib_ver.h>
#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_TIME_H
# include <time.h>
#endif

/** @file fb_lib.c
 * @author Brett Carrington
 *
 * @brief Most general library functions and all UDP transmission and
 * reception functions
 *
 *
 * @mainpage The foneBRIDGE library
 *
 *  The libfb library provides a comprehensive package for configuring
 * and querying foneBRIDGE-based hardware devices over UDP and raw
 * Ethernet. The library tracks the context of individual devices and
 * handles all connections and data transmission using libnet and
 * libpcap.
 *
 * The library is reentrant in the sense that different context
 * pointers (devices) cannot effect each other. Each device must
 * obtain a unique context using libfb_init() and then a connection to
 * the device must be established with libfb_connect(). Multiple
 * contexts to the same device produced undefined behavior.
 *
 */

/************ Prototypes and Constants ***************/
static int set_filter (libfb_t * f, bpf_u_int32 mask);

/** Valid configuations for longhaul LBOs*/
const unsigned char longlbo[MAX_LONGLBO] = {
  PULS_LBO0,
  PULS_LBO1,
  PULS_LBO2,
  PULS_LBO3
};

/** Valid configuations for shorthaul LBOs*/
const unsigned char shortlbo[MAX_SHORTLBO] = {
  PULS_133,
  PULS_266,
  PULS_399,
  PULS_533,
  PULS_655
};

/** Table of libfb error strings */
const char *fberrstr[] = {
  "Success",
  "Try Again (Would Block)",
  "Timed Out",
  "Check System Errno",
  "Invalid Argument",
  "Invalid Bytecount",
  "Exceeded System Maximum or Limit"
};

/** Table of DOOF error strings (from the device) */
const char *dooferrstr[] = {
  "Success",
  "Failed CRC",
  "No Memory Available",
  "Invalid Command",
  "Out of Bounds",
  "No Device Present",
  "Bad Packet Length",
  "Bad Parameter"
};

/************ Setup Functions ***************/

/** @brief Print version information to stdout */
void
libfb_printver ()
{
  printf ("libfb Version %s, Build %d\n", FBLIB_VER, FBLIB_BUILD_NUM);
}

/** @brief Library initalization routine
 * 
 * This sets up the library to begin operation with a device. It
 * returns the context pointer needed for almost all operations.
 *
 * @param device the name of the ethernet device if raw ethernet is used, otherwise NULL
 * @param ethernet one of LIBFB_ETHERNET_OFF or LIBFB_ETHERNET_ON
 * @param errstr A buffer of at least length LIBFB_ERRBUF_SIZE to store an error message
 * @return The initalized context pointer, or NULL is an error occurs 
 */
libfb_t *
libfb_init (char *device, int ethernet, char *errstr)
{
  libfb_t *f;

  bpf_u_int32 mask;		/* The netmask of our sniffing device */
  bpf_u_int32 net;		/* The IP of our sniffing device */

  f = malloc (sizeof (libfb_t));
  if (f == NULL)
    {
      strncpy (errstr, "Fatal error, could not allocate memory!\n",
	       LIBFB_ERRBUF_SIZE);
      return NULL;
    }

  memset (f, 0, sizeof (libfb_t));

  f->udp_socket = -1;

  if ((f->ether_on = ethernet) == LIBFB_ETHERNET_ON)
    {

      if (device == NULL)
	{
	  strncpy (errstr, "Fatal error, no device specified!\n",
		   LIBFB_ERRBUF_SIZE);
	  goto init_error_out_1;

	}

      f->s_mac = get_local_mac (device);
      if (f->s_mac == NULL)
	{
	  strncpy (errstr, "Unable to lookup local MAC address!\n",
		   LIBFB_ERRBUF_SIZE);
	  goto init_error_out_1;
	}

      f->l = libnet_init (LIBNET_LINK, device, errstr);
      if (f->l == NULL)
	goto init_error_out_2;	/* libnet/libpcap will fill out errstr from here on in */

      /* look up netmask */
      if (pcap_lookupnet (device, &net, &mask, errstr) == -1)
	{
	  fprintf (stderr,
		   "[Warning] Can't get netmask for device %s\n", device);
	  net = 0;
	  mask = 0;
	}

      /* open pcap */
      f->p = pcap_open_live (device, 512, 0, 0, errstr);
      if (f->p == NULL)
	goto init_error_out_3;

      /* set up pcap filter */
      if (set_filter (f, mask) == -1)
	{
	  strncpy (errstr, pcap_geterr (f->p), LIBFB_ERRBUF_SIZE);
	  goto init_error_out_4;
	}
    }				/* end of ethernet enabling functions */

  f->crc_en = 0;
  f->device = device;
  return f;

  /* Error handling, free up things we've allocated */
init_error_out_4:
  pcap_close (f->p);
init_error_out_3:
  libnet_destroy (f->l);
init_error_out_2:
  free (f->s_mac);
init_error_out_1:
  free (f);
  return NULL;
}


/** @brief Connect to a device via UDP sockets
 *
 * This is usually the first operation done after obtaining the
 * context pointer with libfb_init. Communication with the device via
 * UDP is not possible until this connection is established. 
 *
 * @param f the device context pointer
 * @param host null-terminated string representing the hostname (or IP address) of the device
 * @param port the UDP port to use, historically 1024 has been used for foneBRIDGE-type devices
 * @return an fblib_err error code, or FBLIB_ESUCCESS if successfully connected
 */
fblib_err
libfb_connect (libfb_t * f, const char *host, int port)
{
  struct hostent *hostPtr = NULL;
  struct sockaddr_in dSock = { 0 };

  f->udp_socket = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (f->udp_socket == -1)
    return FBLIB_EERRNO;

  hostPtr = gethostbyname (host);
  if (hostPtr == NULL)
    {
      hostPtr = gethostbyaddr (host, strlen (host), AF_INET);
      if (hostPtr == NULL)
	return FBLIB_EHERRNO;
    }

  dSock.sin_family = AF_INET;
  dSock.sin_port = htons (port);
  memcpy (&dSock.sin_addr, hostPtr->h_addr, hostPtr->h_length);

  if ((connect (f->udp_socket, (struct sockaddr *) &dSock, sizeof (dSock))) ==
      -1)
    return FBLIB_EERRNO;

  f->connected = 1;
  return FBLIB_ESUCCESS;
}

/** \brief Internal function to set up libpcap filter for 0xD00F packets
 *
 * \param f must be a libfb_t context with a valid pcap context
 * \param mask the netmask on the interface the context operates on
 * \return 0 on success, -1 if a failure occured
 */
static int
set_filter (libfb_t * f, bpf_u_int32 mask)
{
  struct bpf_program filter;
  char m_str[] = "00:00:00:00:00:00";
  char filterstr[128];

  strcpy (filterstr, "ether proto 0xd00f and ether dst ");
  sprintf (m_str, "%02X:%02X:%02X:%02X:%02X:%02X",
	   f->s_mac[0], f->s_mac[1], f->s_mac[2],
	   f->s_mac[3], f->s_mac[4], f->s_mac[5]);

  if (pcap_compile (f->p, &filter, strcat (filterstr, m_str), 0, mask) == -1)
    return -1;

  if (pcap_setfilter (f->p, &filter) == -1)
    return -1;

  return 0;
}


/** @brief Set reference times for printing date information
 *
 * This must be called before the libfb_get-ctime and
 * libfb_get_systime functions are used.
 *
 * @param f the device context
 */
void
set_reftime (libfb_t * f)
{
  struct tm time_info;

  /* Set ref. time to Jan 1st 2000 */
  memset (&time_info, 0, sizeof (struct tm));
  time_info.tm_mday = 1;
  time_info.tm_mon = 0;
  time_info.tm_year = 100;
  f->ref_ctime = mktime (&time_info);

  /* Set the reference for the SYSID timestamp */
  time_info.tm_year = 70;
  f->sysid_ctime = mktime (&time_info);
}

/**
 *  @brief Get the flash date information
 *  @param f the device context
 *  @return the flash date 
 */
inline time_t
libfb_get_ctime (libfb_t * f)
{
  return f->ref_ctime;
}

/**
 * @brief get the sysid time stamp
 * @param f the device context
 * @return the sysid time stamp
 */
inline time_t
libfb_get_systime (libfb_t * f)
{
  return f->sysid_ctime;
}

/************ Shutdown Functions ***************/

/** @brief free resources used by the library 
 *
 * @param f the context owning the resources
 * @return always succeeds with FBLIB_ESUCCESS
 */
fblib_err
libfb_destroy (libfb_t * f)
{
  if (f)
    {
      if (f->connected)
	close (f->udp_socket);

      if (f->p)
	pcap_close (f->p);

      if (f->l)
	libnet_destroy (f->l);

      if (f->s_mac)
	free (f->s_mac);

      free (f);
    }

  return FBLIB_ESUCCESS;
}



/************ FB Query Functions ***************/
/** @brief print the device static information to stream
 *
 * @param f the device context
 * @param stream the output stream (i.e. stdout, stderr...)
 * @param packet_in the DOOF_STATIC_INFO data structure containing the information to display
 */
void
fprint_static_info (libfb_t * f, FILE * stream, DOOF_STATIC_INFO * packet_in)
{
  struct tm *time_info = malloc (sizeof (struct tm));
  time_t calendar_time;

  set_reftime (f);

  fprintf (stream, "SW ver: %s\n", packet_in->sw_ver);
  fprintf (stream, "SW Compile date: %s\n", packet_in->sw_compile_date);
  fprintf (stream, "Build number: %d\n", packet_in->build_num);
  fprintf (stream, "FB core ver sig: 0x%X\n", packet_in->fb_core_version);
  fprintf (stream, "Spans: %d Devices: %d MACs: %d\n", packet_in->spans,
	   packet_in->devices, packet_in->mac_num);
  fprintf (stream, "EPCS Blocks: %d\n", packet_in->epcs_blocks);
  fprintf (stream, "EPCS Block size: 0x%X (%d KB)\n",
	   packet_in->epcs_block_size, packet_in->epcs_block_size / 1024);
  fprintf (stream, "EPCS Region size: 0x%X (%d KB)\n",
	   packet_in->epcs_region_size, packet_in->epcs_region_size / 1024);
  fprintf (stream, "\nStored config data:\n");
  fprintf (stream, "--------------------\n");
  fprintf (stream, "MAC[0]: ");
  fprint_mac (stream, packet_in->epcs_config.mac_addr);
  packet_in->epcs_config.mac_addr[5]++;
  fprintf (stream, "MAC[1]: ");
  fprint_mac (stream, packet_in->epcs_config.mac_addr);
  fprintf (stream, "Serial: %s\n", packet_in->epcs_config.snumber);
  fprintf (stream, "IP[0]: ");
  fprint_ip (stream, packet_in->epcs_config.ip_address[0]);
  fprintf (stream, "IP[1]: ");
  fprint_ip (stream, packet_in->epcs_config.ip_address[1]);
  fprintf (stream, "CFG Flags: 0x%X (%s)\n",
	   packet_in->epcs_config.cfg_flags,
	   packet_in->epcs_config.cfg_flags & (1 << 0) ? "IEC" : "FB2");
  calendar_time = packet_in->epcs_config.mfg_date + libfb_get_ctime (f);
  time_info = localtime (&calendar_time);
  fprintf (stream, "Flash Date: %d (%d/%d/%d %d:%d:%d)\n",
	   (int) calendar_time, time_info->tm_mon + 1, time_info->tm_mday,
	   time_info->tm_year + 1900, time_info->tm_hour, time_info->tm_min,
	   time_info->tm_sec);
  fprintf (stream, "CRC: 0x%X\n", packet_in->epcs_config.crc16);
  fprintf (stream, "SYSID CRC: 0x%X\n", packet_in->fpga_sysid);
  calendar_time = packet_in->fpga_timestamp + libfb_get_systime (f);

  time_info = localtime (&calendar_time);
  fprintf (stream, "SYSID Timestamp: 0x%X (%d/%d/%d %d:%d:%d)\n",
	   packet_in->fpga_timestamp,
	   time_info->tm_mon + 1, time_info->tm_mday,
	   time_info->tm_year + 1900, time_info->tm_hour, time_info->tm_min,
	   time_info->tm_sec);
  fprintf (stream, "Attempted boots: %d\n",
	   packet_in->epcs_config.attempted_boots);
  fprintf (stream, "GPAK File Length: %d bytes\n",
	   packet_in->epcs_config.gpak_len);
  fprintf (stream, "\nDSP Parameters\n-----------------\n");
  fprintf (stream, "Active/Max channels: %d/%d\n",
	   packet_in->gpak_config.active_channels,
	   packet_in->gpak_config.max_channels);
  fprintf (stream, "BIST: %d Num EC: %d\n", packet_in->gpak_config.bist,
	   packet_in->gpak_config.num_ec);
  fprintf (stream, "Stream0: Max channels: %d Supported channels: %d\n",
	   packet_in->gpak_config.stream_slots[0],
	   packet_in->gpak_config.stream_supported_slots[0]);
  fprintf (stream, "Stream1: Max channels: %d Supported channels: %d\n",
	   packet_in->gpak_config.stream_slots[1],
	   packet_in->gpak_config.stream_supported_slots[1]);
  fprintf (stream, "GPAK VerID: 0x%X\n", packet_in->gpak_config.ver);
}

/** @brief print the device static information to stdout
 *
 * @param f the device context
 * @param packet_in the DOOF_STATIC_INFO data structure containing the information to display
 */
void
print_static_info (libfb_t * f, DOOF_STATIC_INFO * packet_in)
{
  fprint_static_info (f, stdout, packet_in);
}

/** @brief get the DOOF_STATIC_INFO information from a device using raw Ethernet
 * 
 * @param f the device context
 * @param dest_mac the destination MAC address
 * @param doof_info pointer to location to store the DOOF_STATIC_INFO
 * @return returns the length of the DOOF response
 */
int
get_static_info (libfb_t * f, unsigned char *dest_mac,
		 DOOF_STATIC_INFO * doof_info)
{
  return get_epcs_pointer (f, dest_mac, doof_info);
}

/** @brief workhorse function for get_static_info
 *
 *  @param f the device context
 *  @param dest_mac the destination MAC address
 *  @param ptr pointer to a buffer to store the DOOF_STATIC_INFO in
 *  @return returns the length of the DOOF response
 */
int
get_epcs_pointer (libfb_t * f, unsigned char *dest_mac,
		  DOOF_STATIC_INFO * ptr)
{
  int res;
  unsigned char recv_buf[1500];

  res =
    doof_txrx (f, dest_mac, NULL, DOOF_CMD_GET_STATIC_INFO, 0, 0, recv_buf);

  if (res < 0)
    return res;

  if (res != sizeof (DOOF_STATIC_INFO))
    {
      printf ("get_static_info: Incorrent byte-length received (%d)\n", res);
      return -DOOF_RESP_BADSIZE;
    }


  memcpy ((unsigned char *) ptr, recv_buf + DOOF_PL_OFF + 14,
	  sizeof (DOOF_STATIC_INFO));

  return 0;
}

/************ End FB Query Functions ***********/

/********************** UDP Functions *******************/
/** @brief the modern way to get the DOOF_STATIC_INFO information 
 *
 * @param f the device context
 * @param dsi location to store the DOOF_STATIC_INFO information in
 * @return an fblib_err representing success or failure
 */
fblib_err
udp_get_static_info (libfb_t * f, DOOF_STATIC_INFO * dsi)
{
  unsigned char buffer[1500];
  ssize_t status;
  fblib_err ret;
  /* getinfo */
  buffer[0] = 0;
  buffer[1] = DOOF_CMD_GET_STATIC_INFO;

  /* write packet */
  if (!udp_ready_write (f))
    return FBLIB_EAGAIN;

  status = write (f->udp_socket, buffer, 2);
  if (status == -1)
    return FBLIB_EERRNO;

  /* read back */
  ret = poll_for_newpkt (f);
  if (ret != FBLIB_ESUCCESS)
    return ret;

  status = read (f->udp_socket, buffer, sizeof (buffer));

  /* Check length */
  if (status != (2 + sizeof (DOOF_STATIC_INFO)))
    {
      return -DOOF_RESP_BADSIZE;
    }
  /* Length is correct */
  memcpy ((void *) dsi, buffer + 2, sizeof (DOOF_STATIC_INFO));

  return FBLIB_ESUCCESS;
}

/** @brief Execute a DOOF_CMD_READ_DSP command
 *
 * @attention This needs better documentation. 
 * 
 * @param f the device context
 * @param address the DSP address to read
 * @param len the payload length? 
 * @param intbuf memory location to store response
 * @return an fblib_err representing success or failure
 */
fblib_err
readdsp (libfb_t * f, unsigned int address, size_t len, unsigned int *intbuf)
{
  unsigned char buffer[1500];
  DOOF_BLK *doof_blk;
  ssize_t status;
  fblib_err ret;

  /* First token is cmd */
  buffer[0] = 0;
  buffer[1] = DOOF_CMD_READ_DSP;
  doof_blk = (DOOF_BLK *) (buffer + 2);
  doof_blk->addr = address;
  doof_blk->len = len;

  if (len == 0)
    return FBLIB_EINVAL;


  if (!udp_ready_write (f))
    return FBLIB_EAGAIN;

  write (f->udp_socket, buffer, sizeof (DOOF_BLK) + 2);

  /* read back */
  ret = poll_for_newpkt (f);
  if (ret != FBLIB_ESUCCESS)
    return ret;

  status = read (f->udp_socket, buffer, sizeof (buffer));

  if (buffer[1])
    {
      printf ("Error code reported from device: %d\n", buffer[1]);
      return -buffer[1];
    }

  if (status != (len * 4 + sizeof (DOOF_BLK) + 2))
    {
      printf ("Error in byte-count received\n");
      return -DOOF_RESP_BADSIZE;
    }
  memcpy ((void *) intbuf, (void *) buffer + sizeof (DOOF_BLK) + 2, len * 4);
  return 0;
}

/** @brief Write to a DSP address
 *
 * @attention This needs better documentation. 
 * 
 * @param f the device context
 * @param address the DSP address to write to
 * @param len the payload length
 * @param intbuf memory location of buffer
 * @return an fblib_err representing success or failure
 */
fblib_err
writedsp (libfb_t * f, unsigned int address, size_t len, unsigned int *intbuf)
{
  unsigned char buffer[1500];
  unsigned int *intptr;
  ssize_t status;
  fblib_err ret;

  DOOF_BLK *doof_blk;
  buffer[0] = 0;
  buffer[1] = DOOF_CMD_WRITE_DSP;
  doof_blk = (DOOF_BLK *) (buffer + 2);

  doof_blk->addr = address;
  doof_blk->len = len;

  intptr = (unsigned int *) (buffer + sizeof (DOOF_BLK) + 2);
  memcpy ((void *) intptr, intbuf, len * 4);
  write (f->udp_socket, buffer, sizeof (DOOF_BLK) + 2 + len * 4);

  /* read back */
  ret = poll_for_newpkt (f);
  if (ret != FBLIB_ESUCCESS)
    return ret;

  status = read (f->udp_socket, buffer, sizeof (buffer));

  if (buffer[1])
    {
      fprintf (stderr, "Error code reported from device: %d\n", buffer[1]);
      return -buffer[1];
    }

  if (status != (sizeof (DOOF_BLK) + 2))
    return FBLIB_EBYTECOUNT;

  return FBLIB_ESUCCESS;
}


/** @brief Set the echo canceller channel types for the entire DSP
 * 
 * We only set one group of types at a time, mask represents which channels get those types.
 *
 * @param f the device context
 * @param type the DSP channel type value
 * @param mask array of masks, 32 bits (one bit per channel) for each span. Each array index is one span. 
 * @return an fblib_err representing success or failure
 */
fblib_err
ec_set_chantype (libfb_t * f, unsigned char type, uint32_t * mask)
{
  unsigned char buffer[1500];
  unsigned char *charptr;
  ssize_t status;
  unsigned int x;
  fblib_err ret;
  buffer[0] = type;
  buffer[1] = DOOF_CMD_EC_CHAN_TYPE;
  charptr = buffer + 2;

  for (x = 0; x < 16; x++)
    {
      *charptr++ = (mask[x / 4] >> ((x % 4) * 8)) & 0xff;
    }

  if (!udp_ready_write (f))
    return FBLIB_EAGAIN;

  status = write (f->udp_socket, buffer, 4 * 4 + 2);
  if (status == -1)
    return FBLIB_EERRNO;

  /* read back */
  ret = poll_for_newpkt (f);
  if (ret != FBLIB_ESUCCESS)
    return ret;

  status = read (f->udp_socket, buffer, sizeof (buffer));
  if (buffer[1])
    {
      printf ("Error code reported from device: %d\n", buffer[1]);
      return -buffer[1];
    }

  if (status != (2))
    {
      return FBLIB_EBYTECOUNT;
    }
  return FBLIB_ESUCCESS;
}

/** @brief Send a custom DOOF command over UDP
 *
 * @param f the device context
 * @param cmd the DOOF command to send
 * @param param optional parameters to the DOOF command
 * @param buf payload to send with the command
 * @param len the length of the payload
 * @return an fblib_err representing success or failure 
 */
fblib_err
custom_cmd (libfb_t * f, unsigned char cmd, unsigned char param, char *buf,
	    size_t len)
{
  unsigned char buffer[1500];
  ssize_t status;
  fblib_err ret;

  if (!udp_ready_write (f))
    return FBLIB_EAGAIN;

  buffer[0] = param;
  buffer[1] = cmd;
  memcpy ((void *) buffer + 2, buf, len);

  status = write (f->udp_socket, buffer, 2 + len);
  if (status == -1)
    return FBLIB_EERRNO;

  /* read back */
  ret = poll_for_newpkt (f);
  if (ret != FBLIB_ESUCCESS)
    return ret;

  status = read (f->udp_socket, buffer, sizeof (buffer));
  if (status != (2))
    {
      printf ("Error in byte-count received\n");
      return -DOOF_RESP_BADSIZE;
    }

#ifdef DEBUG
  fprintf (stderr, "{custom_cmd 0x%02X param 0x%02X resp 0x%02X}\n",
	   cmd, param, buffer[1]);
#endif

  return -buffer[1];
}

/** @brief Send a custom DOOF command over UDP and block until a reply is received
 *
 * @param f the device context
 * @param cmd the DOOF command to send
 * @param param optional parameters to the DOOF command
 * @param buf payload to send with the command
 * @param len the length of the payload
 * @param rbuf location to store the reply
 * @param rlen the expected reply length
 * @return an fblib_err representing success or failure 
 */
fblib_err
custom_cmd_reply (libfb_t * f, unsigned char cmd, unsigned char param,
		  char *buf, size_t len, char *rbuf, size_t rlen)
{
  unsigned char buffer[1500];
  ssize_t status;
  fblib_err ret;

  if (!udp_ready_write (f))
    return FBLIB_EAGAIN;

  buffer[0] = param;
  buffer[1] = cmd;
  memcpy ((void *) buffer + 2, buf, len);
  status = write (f->udp_socket, buffer, 2 + len);

  if (status == -1)
    return FBLIB_EERRNO;

  /* read back */
  ret = poll_for_newpkt (f);
  if (ret != FBLIB_ESUCCESS)
    return ret;

  status = read (f->udp_socket, buffer, sizeof (buffer));
  if (status != (rlen + 2))
    {
      printf ("Error in byte-count received\n");
      return -DOOF_RESP_BADSIZE;
    }
  memcpy ((void *) rbuf, buffer + 2, rlen);

#ifdef DEBUG
  fprintf (stderr, "{custom_cmd_reply 0x%02X param 0x%02X resp 0x%02X}\n",
	   cmd, param, buffer[1]);
#endif

  return -buffer[1];
}


/** @brief Needs documentation! */
fblib_err
readmem32 (libfb_t * f, unsigned int address, size_t len, uint32_t * intbuf)
{
  unsigned char buffer[1500];
  DOOF_BLK *doof_blk;
  ssize_t status;
  fblib_err ret;

  /* First token is cmd */
  buffer[0] = 2;		/* Param 2 is for 32-byte */
  buffer[1] = DOOF_CMD_READ_MEM;
  doof_blk = (DOOF_BLK *) (buffer + 2);

  doof_blk->addr = address;
  doof_blk->len = len;

  if (len == 0)
    return FBLIB_EINVAL;

  if (!udp_ready_write (f))
    return FBLIB_EAGAIN;

  status = write (f->udp_socket, buffer, sizeof (DOOF_BLK) + 2);
  if (status == -1)
    return FBLIB_EERRNO;

  /* read back */
  ret = poll_for_newpkt (f);
  if (ret != FBLIB_ESUCCESS)
    return ret;

  status = read (f->udp_socket, buffer, sizeof (buffer));

  if (buffer[1])
    {
      printf ("Error code reported from device: %d\n", buffer[1]);
      return -buffer[1];
    }

  if (status != (len * 4 + sizeof (DOOF_BLK) + 2))
    return FBLIB_EBYTECOUNT;

  memcpy ((void *) intbuf, (void *) buffer + sizeof (DOOF_BLK) + 2, len * 4);
  return FBLIB_ESUCCESS;
}


/** @brief Read arbitrary device memory address
 *
 * @param f the device context
 * @param address the memory address to read
 * @param len the length of the data to read
 * @param charbuf location to store the result
 * @return an fblib_err representing success or failure 
 */
fblib_err
readmem (libfb_t * f, unsigned int address, size_t len, char *charbuf)
{
  unsigned char buffer[1500];
  DOOF_BLK *doof_blk;
  ssize_t status;
  fblib_err ret;

  /* First token is cmd */
  buffer[0] = 0;
  buffer[1] = DOOF_CMD_READ_MEM;
  doof_blk = (DOOF_BLK *) (buffer + 2);


  doof_blk->addr = address;
  doof_blk->len = len;

  if (len == 0)
    return FBLIB_EINVAL;

  if (!udp_ready_write (f))
    return FBLIB_EAGAIN;

  status = write (f->udp_socket, buffer, sizeof (DOOF_BLK) + 2);
  if (status == -1)
    return FBLIB_EERRNO;

  /* read back */
  ret = poll_for_newpkt (f);
  if (ret != FBLIB_ESUCCESS)
    return ret;

  status = read (f->udp_socket, buffer, sizeof (buffer));

  if (buffer[1])
    {
      printf ("Error code reported from device: %d\n", buffer[1]);
      return -buffer[1];
    }

  if (status != (len + sizeof (DOOF_BLK) + 2))
    return FBLIB_EBYTECOUNT;

  memcpy ((void *) charbuf, (void *) buffer + sizeof (DOOF_BLK) + 2, len);
  return FBLIB_ESUCCESS;
}

/** @brief Update and then reset PMON counters/registers
 *
 *
 * @param f the device context
 * @param span the span on the transceiver to access, in the range 0 to 3
 * @return an fblib_err representing success or failure
 */
fblib_err
libfb_updat_pmon (libfb_t * f, uint8_t span)
{
  fblib_err ret;

  /* Force a transition from 0 to 1 */
  ret = writeidt (f, span, 0xC2, 0x0);
  if (ret != FBLIB_ESUCCESS)
    return ret;

  ret = writeidt (f, span, 0xC2, 0x2);
  if (ret != FBLIB_ESUCCESS)
    return ret;

  return FBLIB_ESUCCESS;
}

/** @brief Read an IDT indirect PMON register
 *
 * Registers are 8-bit wide. Reading and companding two registers
 * (like the LCV0/1 register as an example) is not supported. You must
 * do this manually. UPDAT must also be sent manually via
 * libfb_updat_pmon().
 *
 * @param f the device context
 * @param span the span to read from
 * @param address the register address to read
 * @param data location to store 8-bit response
 *
 * @return an fblib_err representing success or failure
 */
fblib_err
libfb_readidt_pmon (libfb_t * f, uint8_t span, uint8_t address,
		    uint8_t * data)
{
  fblib_err ret;
  uint8_t pmonaccess = (address & 0xF) | (((span % 2) & 0xF) << 5);
  int devnum = 0;

  switch (span)
    {
    case 0:
    case 1:
      devnum = 0;
      break;
    case 2:
    case 3:
      devnum = 2;
      break;
    }

  /* Set ADDR and LINKSEL0 */
  ret = writeidt (f, devnum, 0x00E, pmonaccess);
  if (ret != FBLIB_ESUCCESS)
    return ret;

  /* Read DAT */
  ret = readidt (f, devnum, 0x00F, 1, (char *) data);
  if (ret != FBLIB_ESUCCESS)
    return ret;

  return FBLIB_ESUCCESS;
}

/** @brief Write arbitrary transceiver register
 *
 * The address should be of the form 0xAB. The span parameter is used
 * to expand the address into the IDT native register address form of
 * 0xXAB where X is the correct span number on the targeted device.
 *
 * @param f the device context
 * @param span the span we wish to write to
 * @param address the register to write to
 * @param data the 8-bit data to write
 * @return an fblib_err representing success or failure
 */
fblib_err
writeidt (libfb_t * f, unsigned char span, uint8_t address, uint8_t data)
{
  uint8_t buffer[2];

  buffer[0] = address;
  buffer[1] = data;

  return custom_cmd (f, DOOF_CMD_IDT_WRITE_REG, span, buffer, 2);
}

/** @brief Read arbitrary transceiver memory address
 *
 * The address should be of the form 0xAB. The span parameter is used
 * to expand the address into the IDT native register address form of
 * 0xXAB where X is the correct span number on the targeted device.
 *
 * @param f the device context
 * @param span the transceiver we wish to read from
 * @param address the memory address to read
 * @param len the length of the data to read
 * @param charbuf location to store the result
 * @return an fblib_err representing success or failure 
 */
fblib_err
readidt (libfb_t * f, unsigned char span, unsigned int address, size_t len,
	 char *charbuf)
{
  unsigned char buffer[1500];
  DOOF_BLK *doof_blk;
  ssize_t status;
  fblib_err ret;

  /* First token is cmd */
  buffer[0] = span;
  buffer[1] = DOOF_CMD_READ_IDT_REG;
  doof_blk = (DOOF_BLK *) (buffer + 2);

  doof_blk->addr = address;
  doof_blk->len = len;

  if (len == 0)
    return FBLIB_EINVAL;

  if (!udp_ready_write (f))
    return FBLIB_EAGAIN;

  status = write (f->udp_socket, buffer, sizeof (DOOF_BLK) + 2);
  if (status == -1)
    return FBLIB_EERRNO;

  /* read back */
  ret = poll_for_newpkt (f);
  if (ret != FBLIB_ESUCCESS)
    return ret;

  status = read (f->udp_socket, buffer, sizeof (buffer));

  if (status >= 2 && buffer[1])
    {
      printf ("Error code reported from device: %d\n", buffer[1]);
      return -buffer[1];
    }

  if (status != (len + sizeof (DOOF_BLK) + 2))
    return FBLIB_EBYTECOUNT;

  memcpy ((void *) charbuf, (void *) buffer + sizeof (DOOF_BLK) + 2, len);
  return FBLIB_ESUCCESS;
}

/** @brief Get the GPAK_FLASH_PARMS information from a device
 *
 * @param f the device context
 * @param buf location to store the GPAK_FLASH_PARMS
 * @return an fblib_err representing success or failure 
 */
fblib_err
fblib_get_gpakparms (libfb_t * f, GPAK_FLASH_PARMS * buf)
{
  unsigned char buffer[1500];
  ssize_t status;
  fblib_err ret;

  if (buf == NULL)
    return FBLIB_EINVAL;

  /* First token is cmd */
  buffer[0] = 0;
  buffer[1] = DOOF_CMD_GET_GPAK_FLASH_PARMS;

  if (!udp_ready_write (f))
    return FBLIB_EAGAIN;

  write (f->udp_socket, buffer, 2);

  /* read back */
  ret = poll_for_newpkt (f);
  if (ret != FBLIB_ESUCCESS)
    return ret;

  status = read (f->udp_socket, buffer, sizeof (buffer));

  if (buffer[1])
    {
      printf ("Error code reported from device: %d\n", buffer[1]);
      return -buffer[1];
    }

  if (status != (sizeof (GPAK_FLASH_PARMS) + 2))
    return FBLIB_EBYTECOUNT;

  memcpy (buf, buffer + 2, sizeof (GPAK_FLASH_PARMS));
  return FBLIB_ESUCCESS;
}

/** @brief Read a SPI register
 *
 * @param f the device context
 * @param dev the SPI device address
 * @param address the memory address to read from the device, `dev'
 * @param len the length of data to read
 * @param charbuf location to store the result
 * @return an fblib_err representing success or failure 
 */
fblib_err
readspi (libfb_t * f, unsigned char dev, unsigned char address, size_t len,
	 char *charbuf)
{
  unsigned char buffer[1500];
  DOOF_BLK *doof_blk;
  ssize_t status;
  fblib_err ret;

  /* First token is cmd */
  buffer[0] = dev;
  buffer[1] = DOOF_CMD_SPI_READREG;
  doof_blk = (DOOF_BLK *) (buffer + 2);

  doof_blk->addr = address;
  doof_blk->len = len;

  if (len == 0)
    return FBLIB_EINVAL;

  if (!udp_ready_write (f))
    return FBLIB_EAGAIN;

  status = write (f->udp_socket, buffer, sizeof (DOOF_BLK) + 2);
  if (status == -1)
    return FBLIB_EERRNO;

  /* read back */
  ret = poll_for_newpkt (f);
  if (ret != FBLIB_ESUCCESS)
    return ret;

  status = read (f->udp_socket, buffer, sizeof (buffer));

  if (buffer[1])
    {
      printf ("Error code reported from device: %d\n", buffer[1]);
      return -buffer[1];
    }

  if (status != (len + sizeof (DOOF_BLK) + 2))
    return FBLIB_EBYTECOUNT;

  memcpy ((void *) charbuf, (void *) buffer + sizeof (DOOF_BLK) + 2, len);
  return FBLIB_ESUCCESS;
}

/** @brief Write to a SPI register
 *
 * @param f the device context
 * @param dev the SPI device address
 * @param address the memory address to write to the device, `dev'
 * @param len the length of data to write
 * @param charbuf location to data payload
 * @return an fblib_err representing success or failure 
 */
fblib_err
writespi (libfb_t * f, unsigned char dev, unsigned char address, size_t len,
	  char *charbuf)
{
  DOOF_BLK *doof_blk;
  unsigned char buffer[1500];
  unsigned char *charptr;
  ssize_t status;
  fblib_err ret;


  buffer[0] = dev;
  buffer[1] = DOOF_CMD_SPI_WRITEREG;
  doof_blk = (DOOF_BLK *) (buffer + 2);

  doof_blk->addr = address;
  doof_blk->len = len;

  charptr = (unsigned char *) (buffer + sizeof (DOOF_BLK) + 2);
  memcpy ((void *) charptr, charbuf, len);

  if (!udp_ready_write (f))
    return FBLIB_EAGAIN;

  status = write (f->udp_socket, buffer, sizeof (DOOF_BLK) + 2 + len);
  if (status == -1)
    return FBLIB_EERRNO;

  /* read back */
  ret = poll_for_newpkt (f);
  if (ret != FBLIB_ESUCCESS)
    return ret;

  status = read (f->udp_socket, buffer, sizeof (buffer));

  if (status == -1)
    return FBLIB_EERRNO;

  if (buffer[1])
    {
      printf ("Error code reported from device: %d\n", buffer[1]);
      return -buffer[1];
    }

  if (status != (sizeof (DOOF_BLK) + 2))
    return FBLIB_EBYTECOUNT;

  return FBLIB_ESUCCESS;
}

/** @brief get the current link configuration over UDP
 *
 * @param f the device context
 * @param link_cfg A memory location that is at least  IDT_LINKS*sizeof(IDT_LINK_CONFIG) long
 * @return an fblib_err representing success or failure 
 */
fblib_err
configcheck_fb_udp (libfb_t * f, IDT_LINK_CONFIG * link_cfg)
{
  int len = 2 + IDT_LINKS * sizeof (IDT_LINK_CONFIG);
  unsigned char buffer[len];
  ssize_t status;
  fblib_err ret;

  memset ((void *) buffer, 0, len);
  buffer[0] = 0x0;		/* Don't configure any spans */
  buffer[1] = DOOF_CMD_RECONFIG;
  status = write (f->udp_socket, buffer, len);

  if (status == -1)
    return FBLIB_EERRNO;

  /* read back */
  ret = poll_for_newpkt (f);
  if (ret != FBLIB_ESUCCESS)
    return ret;

  status = read (f->udp_socket, buffer, sizeof (buffer));

  if (status == -1)
    return FBLIB_EERRNO;

  if (buffer[1])
    {
      printf ("Error code reported from device: %d\n", buffer[1]);
      return -buffer[1];
    }

  if (status != len)
    return FBLIB_EBYTECOUNT;

  memcpy ((void *) link_cfg, &buffer[2],
	  sizeof (IDT_LINK_CONFIG) * IDT_LINKS);
  return FBLIB_ESUCCESS;
}

/** @brief configure a device using span_mode masks with no LBO information
 * @deprecated span_mode masks are no longer used for configuration
 *
 * @param f the device context
 * @param span_mode configuration masks
 * @return an fblib_err representing success or failure 
 */
fblib_err
config_fb_udp (libfb_t * f, unsigned char *span_mode)
{
  unsigned char zero[] = { 0, 0, 0, 0 };
  return config_fb_udp_lbo (f, span_mode, zero);
}

/** @brief configure a device using modern IDT_LINK_CONFIG data structures
 *
 * @param f the device context
 * @param configs an array of IDT_LINK_CONFIG structures, one for each span
 * @return an fblib_err representing success or failure 
 */
fblib_err
config_fb_udp_linkconfig (libfb_t * f, IDT_LINK_CONFIG * configs)
{
  int len, span;
  unsigned char buffer[1500];
  ssize_t status;
  fblib_err ret;
  IDT_LINK_CONFIG *link_cfg;

  memset ((void *) buffer, 0, sizeof (buffer));

  /* Reconfigure all spans */
  buffer[0] = 0xF;
  buffer[1] = DOOF_CMD_RECONFIG;
  link_cfg = (IDT_LINK_CONFIG *) & (buffer[2]);
  for (span = 0; span < IDT_LINKS; span++)
    memcpy (&link_cfg[span], &configs[span], sizeof (IDT_LINK_CONFIG));

  len = 2 + IDT_LINKS * sizeof (IDT_LINK_CONFIG);
  if (!udp_ready_write (f))
    return FBLIB_EAGAIN;

  status = write (f->udp_socket, buffer, len);
  if (status == -1)
    return FBLIB_EERRNO;

  /* read back */
  ret = poll_for_newpkt (f);
  if (ret != FBLIB_ESUCCESS)
    return ret;

  status = read (f->udp_socket, buffer, sizeof (buffer));

  if (status == -1)
    return FBLIB_EERRNO;

  if (buffer[1])
    {
      printf ("Error code reported from device: %d\n", buffer[1]);
      return -buffer[1];
    }

  if (status != len)
    {
      printf ("Error in byte-count received\n");
      return -DOOF_RESP_BADSIZE;
    }
  return 0;
}

/** @brief configure a device using span_mode masks with LBO information
 * @deprecated span_mode masks are no longer used for configuration
 *
 * @param f the device context
 * @param span_mode configuration masks
 * @param puls an array of LBO, PULS_* settings, one for each span
 * @return an fblib_err representing success or failure 
 */
fblib_err
config_fb_udp_lbo (libfb_t * f, unsigned char *span_mode, unsigned char *puls)
{
  int len, span;
  unsigned char buffer[1500];
  IDT_LINK_CONFIG *link_cfg;
  ssize_t status;
  fblib_err ret;

  memset ((void *) buffer, 0, sizeof (buffer));

  /* Reconfig all spans */
  buffer[0] = 0xF;
  buffer[1] = DOOF_CMD_RECONFIG;
  link_cfg = (IDT_LINK_CONFIG *) & (buffer[2]);

  for (span = 0; span < IDT_LINKS; span++)
    {
      if (span_mode[span] & SPAN_MODE_E1)
	link_cfg->E1Mode = 1;
      if (span_mode[span] & SPAN_MODE_ESF)
	link_cfg->framing = 1;
      if (span_mode[span] & SPAN_MODE_AMI)
	link_cfg->encoding = 1;
      if (span_mode[span] & SPAN_MODE_RBS)
	link_cfg->rbs_en = 1;
      if (span_mode[span] & SPAN_MODE_CRCMF)
	link_cfg->CRCMF = 1;
      if (span_mode[span] & SPAN_MODE_RLB)
	link_cfg->rlb = 1;
      if (span_mode[span] & SPAN_MODE_EQ)
	link_cfg->EQ = 1;

      if (link_cfg->E1Mode == 0)
	{
	  /* PULS[3:0] only for T1/J1 */
	  link_cfg->LBO = puls[span] & 0xF;
	}
      else
	{
	  /* Just ensure PULS[3:0] is 0 for E1 */
	  link_cfg->LBO = 0;
	}

      link_cfg++;
    }
  len = 2 + IDT_LINKS * sizeof (IDT_LINK_CONFIG);

#ifdef DEBUG
  fprintf (stderr, "LBO PULS: ");
  for (span = 0; span < IDT_LINKS; span++)
    {
      fprintf (stderr, "%02X ", puls[span] & 0xF);
    }
  fprintf (stderr, "\n");
  fprintf (stderr, "Uniform(?) span mode: 0x%02X\n", span_mode[0]);
#endif

  if (!udp_ready_write (f))
    return FBLIB_EAGAIN;

  status = write (f->udp_socket, buffer, len);
  if (status == -1)
    return FBLIB_EERRNO;

  /* read back */
  ret = poll_for_newpkt (f);
  if (ret != FBLIB_ESUCCESS)
    return ret;
#ifdef DEBUG
  fprintf (stderr, "Configured UDP socket %d\n", f->udp_socket);
#endif
  status = read (f->udp_socket, buffer, sizeof (buffer));

  if (status == -1)
    return FBLIB_EERRNO;

  if (buffer[1])
    {
      printf ("Error code reported from device: %d\n", buffer[1]);
      return -buffer[1];
    }

  if (status != len)
    {
      printf ("Error in byte-count received\n");
      return -DOOF_RESP_BADSIZE;
    }
  return 0;
}


/** @brief check if CRC checking is enabled
 * @param f the device context
 * @return true if CRC checking is enabled
 */
bool
libfb_getcrc (libfb_t * f)
{
  if (f->crc_en == 1)
    return true;
  return false;
}

/** @brief set CRC checking value
 * @param f the device context
 * @param value 1 for enabling check, 0 to disable
 */
static inline void
libfb_set_crc (libfb_t * f, int value)
{
  f->crc_en = value;
}

/** @brief toggle CRC checking on
 * @param f the device context
 */
void
libfb_setcrc_on (libfb_t * f)
{
  return libfb_set_crc (f, 1);
}

/** @brief toggle CRC checking off
 * @param f the device context
 */
void
libfb_setcrc_off (libfb_t * f)
{
  return libfb_set_crc (f, 0);
}

/** @brief Get the (local) source MAC address
 * @return pointer to the 6-byte MAC address 
 */
u_int8_t *
libfb_getsrcmac (libfb_t * f)
{
  return f->s_mac;
}
