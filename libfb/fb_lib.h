/** @file fb_lib.h
 * 
 * @brief Main libfb include file
 */
#ifdef HAVE_CONFIG_H
# include <libfb/fb_config.h>
#endif

#if defined(STDC_HEADERS) || defined(HAVE_STRING_H)
# include <string.h>
#endif

#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif

#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#if defined(TM_IN_SYS_TIME)
# if HAVE_SYS_TIME_H
#   include <sys/time.h>
# endif
#elif defined(HAVE_TIME_H)
# include <time.h>
#endif

#if defined(HAVE_ARPA_INET_H)
# include <arpa/inet.h>
#elif defined(HAVE_NETINET_IN_H)
# include <netinet/in.h>
#endif

#if HAVE_LIBNET_H
# include <libnet.h>
#endif

#if HAVE_PCAP_H
# include <pcap.h>
#endif

#if defined(HAVE_STDIO_H)
# include <stdio.h>
#endif

#include "./libfb/fb_context.h"

#ifdef VERSION
# define FBLIB_VER VERSION
#endif

#define MAC_NUM 2	    /**< The max number of MAC/PHY pairs */
#define TDM_STREAM_COUNT 6  /**< The number of TDM streams */
#define IDT_LINKS 4	    /**< The maximum number of spans */

#define CRCPOLY 0x1021	    /**< Polynomial used in CRC16 generation */

/** @brief Skeleton 0xD00F packet */
typedef struct
{
  /** foneBRIDGE firmware command */
  uint8_t cmd;
  /** paramaters to the command */
  uint8_t param;
  /** Length of payload in bytes */
  uint16_t len;
  /** CRC16 of the structure with the crc and reserved fields considered */
  uint16_t crc;
  /** reserved for future use */
  unsigned char reserved[2];
} __attribute__ ((packed)) DOOF;

#define DOOF_PL_OFF 8		/**< Offset from DOOF header to payload */

/** 
 * @brief Raw Ethernet packet for 0xD00F configuration
 *
 * For the single unsigned char values we use a bitmask to represent
 * each span. So if you have four E1 spans, E1 = 00001111, in
 * binary. If you have two E1 and two T1 then E1 = 00001100 in
 * binary. Except for LBO and MAC all the fields work this way.
 *
 * @deprecated used only by raw ethernet layer
 */
typedef volatile struct
{
  /** number of spans being configures */
  unsigned char numSpan;
  /** E1 bitmask */
  unsigned char E1;
  /** RBS bitmask */
  unsigned char RBS;
  /** CLK bitmask */
  unsigned char CLK;
  /** AMI bitmask */
  unsigned char AMI;
  /** ESF bitmask */
  unsigned char ESF;
  /** ETH bitmask */
  unsigned char ETH;
  /** CRCMF bitmask */
  unsigned char CRCMF;
  /** LBO configuration for each of 4 spans */
  unsigned char LBO[4];
  unsigned char mac[4][6];
} DOOF_CFG;

/* DOOF Commands */
#define DOOF_CMD_RECONFIG 1		  /**< Reconfigure FB Mode */
#define DOOF_CMD_READ_BLK 2		  /**< Read a block from Flash */
#define DOOF_CMD_WRITE_BLK 3		  /**< Write a block to flash */
#define DOOF_CMD_GET_DIAG 4		  /**< Get diagnostic info */
#define DOOF_CMD_STOP_FLOW 5		  /**< Stop TDMOE flow */
#define DOOF_CMD_START_WRITE 6		  /**< Start write into EPCS device from buffer */
#define DOOF_CMD_GET_STATIC_INFO 7	  /**< Get static information */
#define DOOF_CMD_WRITE_DSP 9		  /**< Write a block of words to the DSP */
#define DOOF_CMD_READ_DSP 10		  /**< Read a block of words from the DSP */
#define DOOF_CMD_SDRAM_TEST 11		  /**< SDRAM Test? */
#define DOOF_CMD_RESET 12		  /**< Reset external devices */
#define DOOF_CMD_READ_MEM 13		  /**< Read any location in SOPC memory */
#define DOOF_CMD_TDM_CTL 14		  /**< Control TDM Cores individually */
#define DOOF_CMD_GPAK_READ_FIFO 15	  /**< Read a FIFO event from the GPAK API */
#define DOOF_CMD_EC_CHAN_TYPE 16	  /**< Set the EC chan type to either data/voice (0=data,1=voice0,2=voice1,3=teardown) */
#define DOOF_CMD_EC_COMP_TYPE 17	  /**< Set the companding type on the EC */
#define DOOF_CMD_SPI_READREG 18		  /**< Read a group of register from SPI device */
#define DOOF_CMD_SPI_WRITEREG 19	  /**< Write a group of registers to SPI device */
#define DOOF_CMD_TDMOE_TXCTL 20		  /**< Enable/disable TDMOE TX */
#define DOOF_CMD_TDMOE_DSTMAC 21	  /**< Set the dest. MAC for TDMOE */
#define DOOF_CMD_PRINT_PERF 22		  /**< Print perf. status to stdout */
#define DOOF_CMD_TDM_LB_SEL 23		  /**< Enable/disable TDM4-5 Loopback */
#define DOOF_CMD_DSP_INIT 24		  /**< DSP init. */
#define DOOF_CMD_GET_GPAK_FLASH_PARMS 25  /**< Get GPAK Flash parms structure */
#define DOOF_CMD_GET_DSP_USAGE 26	  /**< Retrive the CPU usage of the DSP */
#define DOOF_GET_STATS 27
#define DOOF_GET_RBS 28
#define DOOF_RBS_SPY_CTL 29		  /**< Control RBS spying */
#define DOOF_CMD_SETIP 30		  /**< Set the IP address / recalc CRC */
#define DOOF_CMD_LFSR_CHK 31		  /**< Enable LFSR checking for indicated TDM stream */
#define DOOF_CMD_TDM_CTLSTAT 32		  /**< Set/clear bits in CTLSTAT register */
#define DOOF_CMD_EC_SETPARM 33		  /**< Set certain parameters related to EC (sysparms) */
#define DOOF_CMD_SET_PRIORITY 34	  /**< Set the priority of each span */
#define DOOF_CMD_IDT_WRITE_REG 35	  /**< Write IDT register based on span field */
#define DOOF_CMD_READ_IDT_REG 36	  /**< Read IDT registers */
#define DOOF_CMD_TDM_FECTL 37		  /**< Set/clr bits in TDM FE register */
#define DOOF_CMD_TDM_REGCTL 38		  /**< Set/clr/read values in the TDM Cores */
#define DOOF_CMD_KEY_WRITE 41		  /**< Write customer key */
#define DOOF_CMD_CLKSEL_PIO 43
#define DOOF_CMD_TEMP 50

#define DOOF_CMD_EC_SETPARM_TAPLEN 0
#define DOOF_CMD_EC_SETPARM_ADAPT_FREQ 1
#define DOOF_CMD_EC_SETPARM_FIR_SEGS 2
#define DOOF_CMD_EC_SETPARM_FIR_SEGLEN 3
#define DOOF_CMD_EC_SETPARM_COMP_TYPE 4

/* CTLSTAT register bit defines */
#define TDM_CTLSTAT_TXEN (1<<0)		 /**< Transmission enable */
#define TDM_CTLSTAT_RXEN (1<<1)		 /**< Reception enable */
#define TDM_CTLSTAT_TXIE (1<<2)		 /**< TX interrupt enable */
#define TDM_CTLSTAT_RXIE (1<<3)		 /**< RX interrupt enable */
#define TDM_CTLSTAT_TXIF (1<<4)		 /**< TX interrupt flag */
#define TDM_CTLSTAT_RXIF (1<<5)		 /**< RX interrupt flag */
#define TDM_CTLSTAT_RLB (1<<6)		 /**< Remote loopback - loops PCM DOUT (from FE) to PCM DIN */
#define TDM_CTLSTAT_TX_STATIC (1<<7)	 /**< Transmit static byte flag */
#define TDM_CTLSTAT_INTERL (1<<8)	 /**< Data interleaved flag */
#define TDM_CTLSTAT_PRBS (1<<9)		 /**< Replaces a rotating PRBS value in place of msr_readdata */
#define TDM_CTLSTAT_PRBS_CNT (1<<10)	 /**< Turns the PRBS mode into a channel counter */
#define TDM_CTLSTAT_PRBS_DET (1<<11)	 /**< PRBS detect */
/* REGCTL commands */
#define DOOF_CMD_TDM_REGCTL_NOP 0
#define DOOF_CMD_TDM_REGCTL_SET 1
#define DOOF_CMD_TDM_REGCTL_CLR 2
#define DOOF_CMD_TDM_REGCTL_FORCE 3
/* TDM Core register offsets */
#define DOOF_TDM_OFF_CTLSTAT 0
#define DOOF_TDM_OFF_RXBD 1
#define DOOF_TDM_OFF_TXBD 2
#define DOOF_TDM_OFF_TXSTATIC 3
#define DOOF_TDM_OFF_CHAN_NUM 4
#define DOOF_TDM_OFF_PRBS_ERR 5
#define DOOF_TDM_OFF_FE_CTL 6
#define DOOF_TDM_OFF_MC 7

#define DOOF_BLK_HDR_LEN 8

/** Default chip size - 16 Mbit = 2 Mbyte */
#define EPCS_SPAN (2*(1<<20))
/** EPCS block size */
#define EPCS_BLK_SIZE (1<<16)

/** Timeout period while waiting for packets, in seconds */
#define FBLIB_POLLTIMEOUT       10

/** Error conditions that can be reported by the libfb library */
typedef enum
{
  FBLIB_ESUCCESS = 0,		/**< Success */
  FBLIB_EAGAIN,			/**< Poll failed */
  FBLIB_ETIMEDOUT,		/**< Time out waiting for packet */
  FBLIB_EERRNO,			/**< Check errno */
  FBLIB_EINVAL,			/**< Invalid arguments */
  FBLIB_EBYTECOUNT,		/**< Received incorrect packet length */
  FBLIB_EMAXIMUMS,		/**< Exceeded maximum (threads, sockets...) */
  FBLIB_EEXTLIB,		/**< External library error */
  FBLIB_EHERRNO,		/**< Check h_errno */
  FBLIB_EMAX
} fblib_err;

/** Error conditions that can be reported by the device */
typedef enum
{
  DOOF_RESP_NOERROR = 0,	/**< Success */
  DOOF_RESP_CRCFAIL = 1,	/**< CRC Check Failed */
  DOOF_RESP_NOMEM,		/**< No Memory Available */
  DOOF_RESP_NOCMD,		/**< Invalid Command */
  DOOF_RESP_OOB,		/**< Out of Bounds */
  DOOF_RESP_NODEV,		/**< No such device */
  DOOF_RESP_BADSIZE,		/**< Bad packet length */
  DOOF_RESP_BADPARM,		/**< Bad parameter specified */
  DOOF_RESP_MAXERROR
} doof_err;

extern const char *fberrstr[];
extern const char *dooferrstr[];

/** Convert a libfb error into a string representation */
#define FBERR_STR(errnum)   "libfb: %s\n", fberrstr[errnum]
/** Convert a device error into a string representation */
#define DOOFERR_STR(errnum) "libfb: %s\n", dooferrstr[errnum]


/** @brief Print a libfb error message to stderr
 * 
 * Nothing happens if the error is not a real error code or if the
 * error is FBLIB_ESUCCESS
 */
#define FBERR_PRINT_IF_FAIL(errnum)           \
do {                                          \
  if (errnum > FBLIB_ESUCCESS &&              \
      errnum < FBLIB_EMAX )                   \
	 fprintf(stderr, FBERR_STR(errnum));  \
  else if (errnum != FBLIB_ESUCCESS)          \
   fprintf(stderr, "libfb: Unknown Error\n"); \
} while (0)

/** @brief Print a device error message to stderr
 * 
 * Nothing happens if the error is not a real error code or if the
 * error is DOOF_RESP_NOERROR
 */
#define DOOFERR_PRINT_IF_FAIL(errnum)         \
do {                                          \
  if (errnum > DOOF_RESP_NOERROR &&           \
      errnum < DOOF_RESP_MAXERROR )           \
         fprintf(stderr, DOOFERR_STR(errnum));\
  else if (errnum != DOOF_RESP_NOERROR)       \
   fprintf(stderr,                            \
     "libfb: Unknown remote device error\n"); \
} while (0)

/** @brief Print an error message to stderr
 *
 * Negative error codes are mapped to DOOF_RESP_* (device) errors and
 * positive errors are mapped to libfb errors. If the error code is
 * '0' or if the error code is not a valid error then nothing is
 * printed.
 */
#define PRINT_MAPPED_ERROR_IF_FAIL(errnum)    \
do {                                          \
  if (errnum < 0)                             \
    DOOFERR_PRINT_IF_FAIL(-errnum);           \
  else if (errnum > 0)                        \
    FBERR_PRINT_IF_FAIL(errnum);              \
} while (0)

/** @brief Header for DOOF_BLK packets */
typedef struct
{
  /** Start address */
  uint32_t addr;
  /** Length of payload */
  uint16_t len;
} __attribute__ ((packed)) DOOF_BLK;

/** uLaw (mu-Law) companding type for GPAK DSP */
#define DSP_COMP_TYPE_ULAW 3
/** A-law companding type for GPAK DSP */
#define DSP_COMP_TYPE_ALAW 4

/* LBO PULS[3:0] Settings */
#define PULS_LBO3 (0x09)	/**< -22.5 dB */
#define PULS_LBO2 (0x0A)	/**< -15.0 dB */
#define PULS_LBO1 (0x0B)	/**<  -7.5 dB */
#define PULS_LBO0 (0x02)	/**<   0.0 dB */


#define MAX_LONGLBO 4		/**< The number of valid longhaul LBO
				   settings */
extern const unsigned char longlbo[MAX_LONGLBO];

/* Preset Templates */
#define PULS_655  (0x6)		/**< 533 ~ 655 ft */
#define PULS_533  (0x5)		/**< 399 ~ 533 ft */
#define PULS_399  (0x4)		/**< 266 ~ 399 ft */
#define PULS_266  (0x3)		/**< 133 ~ 266 ft */
#define PULS_133  (0x2)		/**<   0 ~ 133 ft */
#define PULS_J1   (0x2)		/**< J1: 0~655 ft */

#define MAX_SHORTLBO 5		/**< The number of valid shorthaul LBO
				   settings */
extern const unsigned char shortlbo[MAX_SHORTLBO];

/* deprecated span_mode mask flags */
#define SPAN_MODE_EQ    (1<<7) /**< equalizer on */
#define SPAN_MODE_RLB   (1<<6) /**< remote loopback */
#define SPAN_MODE_CRCMF (1<<5) /**< crcmf on */
#define SPAN_MODE_RBS   (1<<4) /**< rbs enabled */
/* #define SPAN_MODE_ETH (1<<3) */
#define SPAN_MODE_E1    (1<<2) /**< E1 mode */
#define SPAN_MODE_ESF   (1<<1) /**< ESF mode */
#define SPAN_MODE_AMI   (1<<0) /**< AMI framing */

#define MAC_SZ     6	       /**< MAC address length in bytes */
#define SERIAL_SZ 16	       /**< Serial number length in bytes */

typedef unsigned char MAC_ADDR[MAC_SZ];	   /**< MAC address typedef */
typedef unsigned char SERIAL[SERIAL_SZ];   /**< Serial number typedef */

/** @brief DSP subsystem (software) information
 * 
 * Represents the detected number of channels, the number of active
 * (configured) channels, and versioning information about the GPAK
 * software.
 *
 * @attention <b>It is absolutely critical that these structures
 * maintain an EIGHT BYTE alignment.</b>
 */
typedef struct
{
  /** The maximum number of channels the hardware DSP supports, this should be '128' if the GPAK software was loaded correctly */
  uint8_t max_channels;
  /** The number of 'running' (properly configured) channels  */
  uint8_t active_channels;
  uint8_t stream_slots[2];
  uint8_t stream_supported_slots[2];
  uint8_t bist;
  uint8_t num_ec;
  /** GPAK software version */
  uint32_t ver;
  /** Reserved fields */
  uint8_t res[4];
} __attribute__ ((packed)) GPAK_SYS_CONFIG;

/** @brief Persistant configuration information about the device that is stored in EPCS flash
 * @details Sizeof EPCS_CONFIG is currently 256 bytes 
 */
typedef struct
{
  /** The device's first MAC address */
  unsigned char mac_addr[MAC_SZ];
  /** Two IP addresses represented in big endian */
  uint32_t ip_address[2];
  /** Bitmask representing configuration flags applicable to the device.
   * @details Documentation of valid flags is specified in firmware source code.
   */
  unsigned char cfg_flags;
  /** reserved field */
  unsigned char res;
  /** a cfg_flag used to mark a device as an inline echo canceller 
   * @details 0 = Fonebridge mode (TDMOE), 1 = IEC mode 
   */
#define CFG_FLAGS_IEC_EN (1<<0)

  /** 32 bit word representing the manufacturing date
   *  @details Number of seconds since Jan 1st 2000 in network byte order. Offset 16 .
   */
  uint32_t mfg_date;

  /** Serial number of the device */
  SERIAL snumber;		/* Off. 20 */

  /** Length in bytes of the stored GPAK file (0 if none) */
  uint32_t gpak_len;		/* Off. 36 */
  unsigned char attempted_boots;	/* Off. 40 - Attempted boots */
  /** Reserved fields */
  unsigned char res2[85];	/* Off. 40 */
  /** Reserved fields */
  unsigned char res3[128];	/* Off. 126 */
  /** CRC16 checksum of this structure, less the crc16 field */
  uint16_t crc16;		/* Off. 254 */
} __attribute__ ((packed)) EPCS_CONFIG;

/** @brief Static device information
 *
 * Current sizeof(DOOF_STATIC_INFO) is 352 bytes. The structure is
 * 'static' in the sense that none of this information is changable by
 * software. It is determined by the firmware and the physical
 * hardware's configuration.
 */
typedef volatile struct
{
  /** software version string as reported by firmware */
  uint8_t sw_ver[16];
  /** software compile date string as reported by firmware */
  uint8_t sw_compile_date[32];	/* Off. 16 */
  /** 16 bit word representing the FB Verilog core version */
  uint16_t fb_core_version;	/* Off. 48 */
  /** 16 bit word representing the build number in firmware */
  uint16_t build_num;
  /** The number of spans found on the device */
  uint8_t spans;		/* Off. 52 */
  /** The number of T1/E1/J1 ICs found in the device. One IC can contain mutiple spans (transceivers.) */
  uint8_t devices;
  /** The number of MAC/PHYs on the device. */
  uint8_t mac_num;
  /** Reserved fields */
  uint8_t res2;

  /** 16 bit word representing the number of flash blocks */
  uint16_t epcs_blocks;		/* Off. 56 */
  /** Reserved fields */
  uint8_t res3[6];
  /** 32 bit word representing the size in bytes of each EPCS block */
  uint32_t epcs_block_size;	/* Off. 64 */

  /** 32 bit word representing the size of the entire EPCS flash,
      i.e. region size is blocks size times the number of blocks */
  uint32_t epcs_region_size;	/* Off. 68 */

  /** EPCS configuration structure which must be aligned to 8-byte boundary */
  EPCS_CONFIG epcs_config;	/* Off. 72 */

  /** 32 bit word representing the FPGA system id tag */
  uint32_t fpga_sysid;		/* Off. 328 */
  /** 32 bit word representing the system id tag timestamp */
  uint32_t fpga_timestamp;	/* Off. 332 */

  /** GPAK configuration data */
  GPAK_SYS_CONFIG gpak_config;	/* Off. 336 */
} __attribute__ ((packed)) DOOF_STATIC_INFO;


/** @brief Convenience structure for representing flash sizes */
typedef struct
{
  unsigned short int epcs_blocks;
  int epcs_block_size;
  int epcs_region_size;
} T_EPCS_INFO;

/** @brief Modern transceiver configuration information 
 * 
 * Each transceiver (span) is configured with one IDT_LINK_CONFIG data
 * structure. The values are generally all binary, although they are
 * transmitted as 8-bit words.
 */
typedef struct
{
  /** Configure span as an E1, 0 = T1/J1, 1 = E1 */
  uint8_t E1Mode;
  /** Configure span as a J1, 0 = T1, 1 = J1 (if E1Mode = 0) */
  uint8_t J1Mode;
  /** Enables ESF framing if true or SF framing if false. Valid for T1s only. */
  uint8_t framing;
  /** Enables AMI encoding if true. When false default is B8ZS (T1) or HDB3 (E1) */
  uint8_t encoding;
  /** Enables RBS functions in the hardware cores, used for T1 RBS and E1 CAS */
  uint8_t rbs_en;
  /** Enables the CRC Multiframe if true (only valid for E1) */
  uint8_t CRCMF;
  /** Places span into "remote loopback mode" if true */
  uint8_t rlb;
  /** Enables automatic equalizer if true, used for longhaul spans */
  uint8_t EQ;
  /** Sets the line build out, see the PULS_XXX defines for allowed values */
  uint8_t LBO;
  /** Reserved fields */
  uint8_t res[7];
} IDT_LINK_CONFIG;

/** @brief Device statistics */
typedef struct
{
  /** Number of packets received on each MAC */
  uint32_t mac_rxcnt[MAC_NUM];
  /** Number of packets transmitted on each MAC */
  uint32_t mac_txcnt[MAC_NUM];
  /** Number of dropped packets on each MAC */
  uint32_t mac_rxdrop[MAC_NUM];
  /** System clock ticks */
  uint8_t ticks[8];
  /** LFSR checking errors for each TDM stream, only vaild when an LFSR check/test is running */
  uint32_t lfsr_err[TDM_STREAM_COUNT];
  uint32_t lfsr_cnt[TDM_STREAM_COUNT];
  /** Reserved fields */
  unsigned char res[32][4];
} __attribute__ ((packed)) DOOF_STATS;

/** @brief DSP configuration 
 *
 * @details Represents the properties and current configuration of the
 * DSP and the GPAK software on a device
 */
typedef struct
{
  /** The DSP channel configuration for all 128 supported channels.
   *
   * The possibilities are:
   * <ul>
   *  <li>Data channel (no echo cancelling): 0</li>
   *  <li>Cancel in direction 'A': 1</li>
   *  <li>Cancel in direction 'B': 2</li>
   *  <li>Disable data transmission: 3</li>
   * </ul>
   */
  uint8_t dsp_chan_type[128];
  /** The companding type used on the channel, one of DSP_COMP_TYPE_ALAW or DSP_COMP_TYPE_ULAW */
  uint8_t dsp_companding_type;
  uint8_t taplen;
  uint8_t adapt_freq;
  uint8_t fir_segs;
  uint8_t fir_seglen;
  /** Reserved fields */
  uint8_t res[3];
} GPAK_FLASH_PARMS;

/* Customer Key Data */
/** The length of the "secret" customer key */
#define CUSTOMER_KEY_SZ 32
/** Length of the hashed key */
#define HASH_KEY_SZ     20
/** Length of the salt used */
#define SALT_SZ          2
/** Length of the base random seed generated */
#define BASE_SEED_SZ    32
/** Total seed side */
#define SEED_SZ         (BASE_SEED_SZ + MAC_SZ + SERIAL_SZ  + SALT_SZ)

/** @brief A single securty key */
typedef struct
{
  /** The one-way hash of the customer key */
  unsigned char hash_key[HASH_KEY_SZ];
  /** The "secret" customer key */
  unsigned char customer_key[CUSTOMER_KEY_SZ];
  /** CRC16 of the fields, less the crc16 field */
  uint16_t crc16;
} __attribute__ ((packed)) KEY_ENTRY;

/* End Key */

/** @brief Representation of a PMON register
 *
 * At a minimum first_address and the two length fields must be set
 * correctly. Data is a pointer to a location of at least size length_bytes
 * that may be used for storing the data held in the physical register.
 *
 * length_bits is used by PMON reading functions to mask off reserved
 * fields.
 *
 */
typedef struct libfb_PMONRegister_
{
  char *name; /**< Optional register name */
  char *longname; /**< Optional description */

  /** First_address is where the first 8 bits are found. We assume
   *  that bits found after the first 8 are found in sequentially
   *  increasing registers. For example if register 0x12 contains the
   *  first 8 bits ([7:0]) then we expect register 0x13 to contain the
   *  next 8 ([15:8])
   */

  uint8_t first_address;

  uint8_t length_bits; /**< Length of data in bits. */
  uint8_t length_bytes;	/**< Length of data in smallest number of bytes. */

  uint8_t *data; /**< Location to store read data */

} libfb_PMONRegister;


extern const libfb_PMONRegister libfb_regs_T1ESF[];

extern const libfb_PMONRegister libfb_regs_T1SF[];

extern const libfb_PMONRegister libfb_regs_E1[];




/***** Function prototypes ******/
/* get_local_mac.c: This file must be ported for each target OS */
u_int8_t *get_local_mac (char *nicname);

/* ethernet.c */
fblib_err send_ethernet (libfb_t * f, u_int8_t * dst_mac, u_int8_t * payload,
			 u_int32_t len);
fblib_err send_doof (libfb_t * f, u_int8_t * dst_mac, u_int8_t * buf,
		     u_int16_t buflen, u_int8_t cmd, u_int8_t param);
int recv_paacket (libfb_t * f, u_int8_t * buffer);
uint16_t recv_doof (libfb_t * f, u_int8_t * buffer);
fblib_err config_fb (libfb_t * f, unsigned char *span_mode,
		     unsigned char *dest_mac, unsigned char fb_mac[][6]);
fblib_err config_fb_allspan_off (libfb_t * f, unsigned char *dest_mac);
int doof_txrx (libfb_t * f, u_int8_t * dstmac, u_int8_t * packet,
	       u_int8_t cmd, u_int8_t param, u_int16_t len,
	       u_int8_t * recv_buf);

/* fb_lib.c */
void libfb_printver ();
int get_static_info (libfb_t * f, unsigned char *dest_mac,
		     DOOF_STATIC_INFO * doof_info);
int get_epcs_pointer (libfb_t * f, unsigned char *dest_mac,
		      DOOF_STATIC_INFO * ptr);
void print_static_info (libfb_t * f, DOOF_STATIC_INFO * packet_in);
libfb_t *libfb_init (char *device, int ethernet, char *errstr);
fblib_err libfb_connect (libfb_t * f, const char *host, int port);
fblib_err libfb_destroy (libfb_t * f);
inline time_t libfb_get_ctime (libfb_t * f);
inline time_t libfb_get_systime (libfb_t * f);
void libfb_setcrc_on (libfb_t * f);
void libfb_setcrc_off (libfb_t * f);
bool libfb_getcrc (libfb_t * f);
u_int8_t *libfb_getsrcmac (libfb_t * f);
void set_reftime (libfb_t * f);
fblib_err libfb_updat_pmon (libfb_t * f, uint8_t span);
fblib_err libfb_readidt_pmon (libfb_t * f, uint8_t span, uint8_t address,
			      uint8_t * data);
fblib_err writeidt (libfb_t * f, unsigned char span, uint8_t address,
		    uint8_t data);
fblib_err readidt (libfb_t * f, unsigned char span, unsigned int address,
		   size_t len, char *charbuf);


/* flash.c */
fblib_err udp_read_blk (libfb_t * f, uint32_t address, uint16_t len,
			uint8_t * buffer);
fblib_err udp_write_to_blk (libfb_t * f, uint32_t address, uint16_t len,
			    uint8_t * buffer);
fblib_err udp_start_blk_write (libfb_t * f, uint32_t address);
int write_to_blk (libfb_t * f, unsigned char *dest_mac, int address,
		  int length, unsigned char *buffer);
int start_blk_write (libfb_t * f, unsigned char *dest_mac, int address);
int read_blk (libfb_t * f, unsigned char *dest_mac, int address, int length,
	      unsigned char *recv_buf);

/* utility.c */
unsigned short crc_16 (unsigned char *buf, int len);
u_int16_t grab16 (const volatile u_int8_t * src);
u_int32_t grab32 (const volatile u_int8_t * src);
void store16 (u_int16_t val, u_int8_t * dst);
void store32 (u_int32_t val, u_int8_t * dst);
void print_current_time (FILE * output);
void fprint_ip (FILE * stream, uint32_t ip);
void print_ip (uint32_t ip);
void fprint_mac (FILE * output, const volatile unsigned char *mac);
void print_mac (const volatile unsigned char *mac);
int parse_mac (char *src_mac, unsigned char *dst_mac);
void print_span_mode_idtlink (IDT_LINK_CONFIG link, FILE * output);
void print_span_mode (unsigned char mode, FILE * output);
void libfb_write_seed (uint8_t * buffer);
int libfb_fprint_key (FILE * stream, KEY_ENTRY * key);

/** Build feature idenfitication macros */
/** @enum FEATURE
 *
 * @brief Possible feature sets that are available on the target device.
 *
 * FEATURE_PRE_2_0: Only feature sets prior to hardware version 2.0. This refers to the old priority scheme where '1' meant master and '0' meant slave.
 *
 * FEATURE_2_0: Only feature sets available in hardware version 2.0
 * are supported. This refers to the priority scheme where '0' means
 * slave to line and values '1-3' represent a priority indication.
 *
 */
typedef enum
{ FEATURE_PRE_2_0, FEATURE_2_0, FEATURE_MAX } FEATURE;

const uint16_t buildnum_featureset[FEATURE_MAX];

#define IS_FEATURE_2_0(x)           ((x >= buildnum_featureset[FEATURE_2_0]) ? 1 : 0)
#define IS_FEATURE_PRE_2_0(x)       ((x <= buildnum_featureset[FEATURE_PRE_2_0]) ? 1 : 0)

FEATURE libfb_feature_set (DOOF_STATIC_INFO *);

/* unsorted so far */
int tx_packet (unsigned char *dest_mac, unsigned char *buffer, int len);
int rx_packet (unsigned char *buffer);
int rx_packet_sock (int socket, unsigned char *buffer);
void fprint_static_info (libfb_t * f, FILE * stream,
			 DOOF_STATIC_INFO * packet_in);
fblib_err udp_get_static_info (libfb_t * f, DOOF_STATIC_INFO * dsi);
fblib_err readdsp (libfb_t * f, unsigned int address, size_t len,
		   unsigned int *intbuf);
fblib_err writedsp (libfb_t * f, unsigned int address, size_t len,
		    unsigned int *intbuf);
fblib_err ec_set_chantype (libfb_t * f, unsigned char type, uint32_t * mask);
fblib_err custom_cmd (libfb_t * f, unsigned char cmd, unsigned char param,
		      char *buf, size_t len);
fblib_err custom_cmd_reply (libfb_t * f, unsigned char cmd,
			    unsigned char param, char *buf, size_t len,
			    char *rbuf, size_t rlen);
fblib_err readmem (libfb_t * f, unsigned int address, size_t len,
		   char *charbuf);
fblib_err readmem32 (libfb_t * f, unsigned int address, size_t len,
		     uint32_t * intbuf);
fblib_err readspi (libfb_t * f, unsigned char dev, unsigned char address,
		   size_t len, char *charbuf);
fblib_err writespi (libfb_t * f, unsigned char dev, unsigned char address,
		    size_t len, char *charbuf);
fblib_err config_fb_udp (libfb_t * f, unsigned char *span_mode);
fblib_err config_fb_udp_lbo (libfb_t * f, unsigned char *span_mode,
			     unsigned char *puls);
fblib_err config_fb_udp_linkconfig (libfb_t * f, IDT_LINK_CONFIG *);
int parseMac (unsigned char *dst, char *mac);
fblib_err fblib_get_gpakparms (libfb_t * f, GPAK_FLASH_PARMS * buf);
fblib_err configcheck_fb_udp (libfb_t * f, IDT_LINK_CONFIG * link_cfg);


/** poll.c **/
bool udp_ready_read (libfb_t * f);
bool udp_ready_write (libfb_t * f);
fblib_err poll_for_newpkt (libfb_t * f);
