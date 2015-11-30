#include <libfb/fb_lib.h>

#if defined(STDC_HEADERS) || defined(HAVE_STDLIB_H)
# include <stdlib.h>
#endif

/**
 * @file flash.c
 *
 * @brief Flash block manipulation commands 
 *
 * Functions not prefixed with udp_* use raw Ethernet communication
 * and should not be used for new applications except when needed for
 * device bring-up.
 *
 */

/** @brief Read from flash memory via UDP
 * 
 *  @param f the device context
 *  @param address the block number (not address) to read
 *  @param len the number of bytes (8-bit words) to read
 *  @param buffer location of at least length, len + sizeof(DOOF_BLK),
 *  to store the read bytes. A DOOF_BLK header is appended in front of
 *  the actual bytes read from flash. 
 *  @return an error code, if applicable
 */
fblib_err
udp_read_blk (libfb_t * f, uint32_t address, uint16_t len, uint8_t * buffer)
{
  fblib_err err;
  DOOF_BLK pkt;
  uint8_t *localbuf;

  localbuf = malloc (sizeof (DOOF_BLK) + len);
  if (localbuf == NULL)
    {
      return FBLIB_EERRNO;
    }
  pkt.addr = address;
  pkt.len = len;

  err = custom_cmd_reply (f, DOOF_CMD_READ_BLK, 0, (char *) &pkt,
			  sizeof (DOOF_BLK), (char *) localbuf,
			  len + sizeof (DOOF_BLK));

  memcpy (buffer, localbuf + sizeof (DOOF_BLK), len);

  free (localbuf);

  return err;
}

/** @brief Load a buffer into a device and prepare it for writing to flash.
 *
 *  This function merely loads the desired buffer onto the device. You
 *  must finish the transaction by calling udp_start_blk_write() on the
 *  same address. 
 *
 *  Only one flash block can be written at a time. The address
 *  represents a relative address in that block, i.e. from
 *  [0..EPCS_BLK_SIZE). Writes must be small, as they are limited to
 *  the maximum UDP/Ethernet packet size. Once all bytes have been
 *  written they must be commited to flash with udp_start_blk_write().
 *
 *  @brief f the device context
 *  @brief address the relative address in a block, i.e. in the set
 *  [0..EPCS_BLK_SIZE).
 *  @brief len the number of bytes to write
 *  @brief buffer a buffer of at least length len containing the data to write
 *  @return an error code if applicable
 */
fblib_err
udp_write_to_blk (libfb_t * f, uint32_t address, uint16_t len,
		  uint8_t * buffer)
{
  fblib_err err;

  uint8_t *vbuf;
  uint8_t *payload;
  DOOF_BLK *pkt;

  vbuf = malloc (len + sizeof (DOOF_BLK));
  if (!vbuf)
    return FBLIB_EERRNO;

  // Build DOOF_BLK in memory
  pkt = (DOOF_BLK *) vbuf;
  pkt->addr = address;
  pkt->len = len;

  // Point to location of payload data and copy that data in
  payload = vbuf + sizeof (DOOF_BLK);
  memcpy (payload, buffer, len);

  err =
    custom_cmd_reply (f, DOOF_CMD_WRITE_BLK, 0, (char *) vbuf,
		      len + sizeof (DOOF_BLK), NULL, 0);
  free (vbuf);
  return err;
}

/** @brief Commit a write into flash memory
 *
 *  @param f the device context
 *  @param address the flash block number (not the address)
 *  @return an error code if applicable
 */
fblib_err
udp_start_blk_write (libfb_t * f, uint32_t blk)
{
  fblib_err err;
  DOOF_BLK pkt;
  pkt.addr = blk;
  pkt.len = 0;

  err =
    custom_cmd_reply (f, DOOF_CMD_START_WRITE, 0, (char *) &pkt,
		      sizeof (DOOF_BLK), NULL, 0);
  return err;
}


/** @brief Prepare a write to a flash block
 *
 * Length in BLK commands refers to payload length only (ie: length to
 * read/write), not complete packet length.  Buffer should point to
 * start of payload, not packet.
 * 
 * @param f the device context
 * @param dest_mac destination MAC address
 * @param address flash block number to write to
 * @param length see above
 * @param buffer payload memory location
 * @return A negative value if failure detected
 */
int
write_to_blk (libfb_t * f, unsigned char *dest_mac, int address, int length,
	      unsigned char *buffer)
{
  DOOF_BLK *packet = malloc (sizeof (DOOF_BLK) + length);
  int res, len = 0;
  void *vptr = (void *) packet;

  unsigned char recv_buf[1500];

  if (length > 256)
    return FBLIB_EINVAL;

  memset ((void *) packet, 0, sizeof (DOOF_BLK) + length);

  packet->addr = address;
  packet->len = length;

  /* The length of the payload to the 0xD00f packet will be the BLK HEADER plus the payload */
  len = sizeof (DOOF_BLK) + length;

  vptr += sizeof (DOOF_BLK);

  memcpy (vptr, buffer, length);

  res =
    doof_txrx (f, dest_mac, (unsigned char *) packet, DOOF_CMD_WRITE_BLK, 0,
	       len, recv_buf);
  free ((void *) packet);
  return res;

}

/** @brief Initiate the write process into flash 
 *
 * Flash writing is transactional. write_to_blk must first be called to load the payload.
 *
 * @param f the device context
 * @param dest_mac destination MAC address
 * @param address flash block number to write to
 * @return 0 on success
 */
int
start_blk_write (libfb_t * f, unsigned char *dest_mac, int address)
{
  DOOF_BLK *packet = malloc (sizeof (DOOF_BLK));
  int res, len = 0;
  unsigned char recv_buf[1500];

  memset ((void *) packet, 0, sizeof (DOOF_BLK));

  packet->addr = address;

  len = sizeof (DOOF_BLK);


  res =
    doof_txrx (f, dest_mac, (unsigned char *) packet, DOOF_CMD_START_WRITE, 0,
	       len, recv_buf);

  free ((void *) packet);
  return res;
}

/** @brief Read 'length' bytes into buffer from address in flash
 * 
 * @param f the device context
 * @param dest_mac destination MAC address
 * @param address flash block number to read from
 * @param length number of bytes to read
 * @param recv_buf memory location to store received payload
 */
int
read_blk (libfb_t * f, unsigned char *dest_mac, int address, int length,
	  unsigned char *recv_buf)
{
  DOOF_BLK *packet = (DOOF_BLK *) malloc (sizeof (DOOF_BLK));
  unsigned char buf[1500];

  int res, len = 0;

  if (length > 256)
    return -FBLIB_EINVAL;

  memset ((void *) packet, 0, sizeof (DOOF_BLK));

  /* Fill out packet fields */

  packet->addr = address;
  packet->len = length;

  len = sizeof (DOOF_BLK);


  res =
    doof_txrx (f, dest_mac, (unsigned char *) packet, DOOF_CMD_READ_BLK, 0,
	       len, buf);
  free ((void *) packet);

  /* Check if we received expected length */
  if (res != length)
    {
      printf ("read_blk: Incorrect byte-count received (%d / %d)\n", res,
	      length);
      return -DOOF_RESP_BADSIZE;
    }

  /* Copy the contents of the payload into the dest. buffer */
  memcpy ((void *) recv_buf, (void *) buf + 14 + DOOF_PL_OFF, length);

  return res;
}
