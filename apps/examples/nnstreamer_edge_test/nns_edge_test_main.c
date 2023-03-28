/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>
#include <netinet/in.h>

#include <wifi_manager/wifi_manager.h>
#include "nnstreamer-edge.h"



unsigned int received;

/**
 * @brief Data struct for options.
 */
typedef struct
{
  char *topic;
  unsigned int port;
  char *dest_host;
  unsigned int dest_port;
  nns_edge_connect_type_e conn_type;
  nns_edge_node_type_e node_type;
	char *ssid;
	char *wifi_pw;
} opt_data_s;
static pthread_mutex_t wifi_mutex;
static pthread_cond_t wifi_cond;

void WIFI_WAIT()
{
  pthread_mutex_lock(&wifi_mutex);
  pthread_cond_wait(&wifi_cond, &wifi_mutex);
  pthread_mutex_unlock(&wifi_mutex);
}

void WIFI_SIGNAL()
{
  pthread_mutex_lock(&wifi_mutex);
  pthread_cond_signal(&wifi_cond);
  pthread_mutex_unlock(&wifi_mutex);
}

void sta_connected (wifi_manager_cb_msg_s msg, void *arg)
{
  printf("sta_connected() res(%d)\n", msg.res);
  WIFI_SIGNAL();
}

void sta_disconnected (wifi_manager_cb_msg_s msg, void *arg)
{
  sleep(1);
  printf("sta_disconnected()\n");
  WIFI_SIGNAL();
}

void softap_sta_join(wifi_manager_cb_msg_s msg, void *arg)
{
  printf("softap_sta_join()\n");
  WIFI_SIGNAL;
}

void softap_sta_leave(wifi_manager_cb_msg_s msg, void *arg)
{
  printf("softap_sta_leave()\n");
  WIFI_SIGNAL;
}

void scan_done(wifi_manager_cb_msg_s msg, void *arg)
{
  printf("scan_done()\n");
  WIFI_SIGNAL;
}

static wifi_manager_cb_s wifi_callbacks = {
  sta_connected,
  sta_disconnected,
  softap_sta_join,
  softap_sta_leave,
  scan_done,
};

int wifi_signal_init (void)
{
  int res = pthread_mutex_init(&wifi_mutex, NULL);

  if (res != 0) {
    printf(" pthread mutex init fail(%d)\n", res);
    return -1;
  }

  res = pthread_cond_init(&wifi_cond, NULL);
  if (res != 0) {
    printf(" conditional mutex init fail(%d)\n", res);
    return -1;
  }

  return 0;
}

void wifi_signal_deinit(void)
{
  pthread_mutex_destroy(&wifi_mutex);
  pthread_cond_destroy(&wifi_cond);
}

/**
 * @brief Edge event callback.
 */
static int
_query_client_event_cb (nns_edge_event_h event_h, void *user_data)
{
  nns_edge_event_e event = NNS_EDGE_EVENT_UNKNOWN;
  nns_edge_data_h data_h;
  void *data;
  nns_size_t data_len;
  unsigned int count;
  int ret;

  printf ("[DEBUG] query client receive event! \n\n");
  ret = nns_edge_event_get_type (event_h, &event);
  if (NNS_EDGE_ERROR_NONE != ret)
    return ret;

  switch (event) {
    case NNS_EDGE_EVENT_NEW_DATA_RECEIVED:
      received++;

      nns_edge_event_parse_new_data (event_h, &data_h);

      nns_edge_data_get_count (data_h, &count);
      nns_edge_data_get (data_h, 0, &data, &data_len);
      nns_edge_data_destroy (data_h);
      printf ("[DEBUG] New data received. the number of mem: %u, size: %u \n",
          count, (unsigned int) data_len);

      break;
    default:
      break;
  }

  return NNS_EDGE_ERROR_NONE;
}

/**
 * @brief Get nnstreamer-edge connection type
 */
static nns_edge_connect_type_e
_get_conn_type (char *arg)
{
  nns_edge_connect_type_e conn_type;

  if (strcmp (arg, "TCP") == 0)
    conn_type = NNS_EDGE_CONNECT_TYPE_TCP;
  else if (strcmp (arg, "HYBRID") == 0)
    conn_type = NNS_EDGE_CONNECT_TYPE_HYBRID;
  else if (strcmp (arg, "MQTT") == 0)
    conn_type = NNS_EDGE_CONNECT_TYPE_MQTT;
  else if (strcmp (arg, "AITT") == 0)
    conn_type = NNS_EDGE_CONNECT_TYPE_AITT;
  else
    conn_type = NNS_EDGE_CONNECT_TYPE_UNKNOWN;

  return conn_type;
}

/**
 * @brief Get nnstreamer-edge node type
 */
static nns_edge_node_type_e
_get_node_type (char *arg)
{
	nns_edge_node_type_e node_type = NNS_EDGE_NODE_TYPE_QUERY_CLIENT;

	if (strcmp (arg, "QUERY") == 0)
		node_type = NNS_EDGE_NODE_TYPE_QUERY_CLIENT;
	else if (strcmp (arg, "PUB") == 0)
    node_type = NNS_EDGE_NODE_TYPE_PUB;
	else
	  node_type = NNS_EDGE_NODE_TYPE_UNKNOWN;

  return node_type;
}

/**
 * @brief Function for getting options
 */
static void
_get_option (int argc, char **argv, opt_data_s *opt_data)
{
  int opt;
  char *optstring = "p:b:d:t:c:n:s:w";

  opt_data->topic = NULL;
  opt_data->port = 0;
  opt_data->dest_host = strdup ("localhost");
  opt_data->dest_port = 5001;
  opt_data->conn_type = NNS_EDGE_CONNECT_TYPE_UNKNOWN;
	opt_data->ssid = strdup ("nnstreamer-internal");
	opt_data->wifi_pw = strdup ("npu2848*");

  while ((opt = getopt (argc, argv, optstring)) != -1) {
    switch (opt) {
      case 'p':
        opt_data->port = (uint) strtoll (optarg, NULL, 10);
        break;
      case 'b':
        free (opt_data->dest_host);
        opt_data->dest_host = strdup (optarg);
        break;
      case 'd':
        opt_data->dest_port = (uint) strtoll (optarg, NULL, 10);
        break;
      case 't':
        free (opt_data->topic);
        opt_data->topic = strdup (optarg);
        break;
      case 'c':
        opt_data->conn_type = _get_conn_type (optarg);
        break;
      case 'n':
        opt_data->node_type = _get_node_type (optarg);
        break;
      case 's':
        free (opt_data->ssid);
        opt_data->ssid = strdup (optarg);
        break;
      case 'w':
        free (opt_data->wifi_pw);
        opt_data->wifi_pw = strdup (optarg);
        break;
      default:
        break;
    }
  }
}

/**
 * @brief Prepare edge data to send
 */
static int
_prepare_edge_data (nns_edge_data_h *data_h)
{
  nns_size_t data_len;
  void *data = NULL;
  int ret = NNS_EDGE_ERROR_NONE;

  data_len = 3 * 224 * 224 * sizeof (char);
  data = malloc (data_len);
  if (!data) {
    printf ("Failed to allocate camera data.\n");
    return NNS_EDGE_ERROR_OUT_OF_MEMORY;
  }

  ret = nns_edge_data_create (data_h);
  if (NNS_EDGE_ERROR_NONE != ret) {
    printf ("Failed to create an edge data.\n");
    return ret;
  }

  ret = nns_edge_data_add (*data_h, data, data_len, free);
  if (NNS_EDGE_ERROR_NONE != ret) {
    printf ("Failed to add camera data to the edge data.\n");
  }

  return ret;
}

int nns_edge_test_main (int argc, char *argv[])
{
	nns_edge_h client_h;
	int ret;
	nns_edge_data_h data_h;
	unsigned int i, retry;
  struct in_addr ip;
	opt_data_s opt_data;
	char *client_host = NULL;
  wifi_manager_info_s info;
	wifi_manager_ap_config_s apconfig;
	wifi_manager_result_e res = WIFI_MANAGER_SUCCESS;

	printf ("\n\n--------------------- Start nnstreamer-edge test on TizenRT.. ---------------------- \n");
	_get_option (argc, argv, &opt_data);
  printf ("[INFO] desthost: %s, destport: %u, topic: %s \n", opt_data.dest_host, opt_data.dest_port, opt_data.topic);

  if (NNS_EDGE_CONNECT_TYPE_UNKNOWN == opt_data.conn_type) {
		printf ("[ERROR] Please set connection type! ex: -c TCP\n");
		return 0;
	}

	if (wifi_signal_init () < 0) {
		printf ("Failed to init wifi signal.\n");
		return 0;
	}

	printf ("\n\n--------------------- wifi_manager_init.. ---------------------- \n");
	wifi_manager_deinit ();
	wifi_signal_deinit ();
	wifi_manager_init (&wifi_callbacks);
	printf ("\n\n--------------------- wifi_manager_init Done.. ---------------------- \n");

  printf ("\n\n--------------------- Before Connect to WiFi AP.. ---------------------- \n");
  strcpy (apconfig.ssid, opt_data.ssid);
	apconfig.ssid_length = strlen (opt_data.ssid) + 1;
	strcpy (apconfig.passphrase, opt_data.wifi_pw);
	apconfig.passphrase_length = strlen (opt_data.wifi_pw) + 1;
	apconfig.ap_auth_type = WIFI_MANAGER_AUTH_WPA2_PSK;
	apconfig.ap_crypto_type = WIFI_MANAGER_CRYPTO_AES;

	printf ("\n\n--------------------- connect to AP.. ---------------------- \n");
	res = wifi_manager_connect_ap (&apconfig);
	if (res != WIFI_MANAGER_SUCCESS) {
		printf("Failed to connect AP, ssid: %s\n", opt_data.ssid);
		wifi_manager_deinit ();
		wifi_signal_deinit ();
		return 0;
	}

	sleep(1);

  printf ("\n\n--------------------- Get wifi manager info.. ---------------------- \n");
  ret = wifi_manager_get_info (&info);
  if (ret != WIFI_MANAGER_SUCCESS) {
    printf("[ERROR] wifi_manager_get_info fail. \n");
    goto done;
	}

	netlib_get_ipv4addr ("wlan0", &ip);
	client_host = strdup (inet_ntoa(ip));
	printf ("\n\n\n [[[[DEBUG]]]]] IP addr: %s \n\n", client_host);
  sleep(1);
  printf ("\n\n--------------------- Create edge handle.. ---------------------- \n");
	ret = nns_edge_create_handle ("TEMP_ID", opt_data.conn_type,
        opt_data.node_type, &client_h);
  if (NNS_EDGE_ERROR_NONE == ret)
	  printf ("[DEBUG] Success to create edge handler\n");
	else
	  printf ("Failed to create edge handler\n");
  sleep(1);
	nns_edge_set_event_callback (client_h, _query_client_event_cb, NULL);

  printf("\n\n[DEBUG] port: %u, dest host: %s, dest port: %u, client_host: %s \n\n",
	    opt_data.port, opt_data.dest_host, opt_data.dest_port, client_host);

	nns_edge_set_info (client_h, "HOST", client_host);
	if (opt_data.topic)
    nns_edge_set_info (client_h, "TOPIC", opt_data.topic);

  if (NNS_EDGE_NODE_TYPE_PUB == opt_data.node_type) {
    if (NNS_EDGE_CONNECT_TYPE_TCP == opt_data.conn_type) {
      char port[6];
      sprintf (port, "%u", opt_data.port);
      nns_edge_set_info (client_h, "PORT", port);
    } else {
      char port[6];
      sprintf (port, "%u", opt_data.dest_port);
      nns_edge_set_info (client_h, "DEST_HOST", opt_data.dest_host);
      nns_edge_set_info (client_h, "DEST_PORT", port);
    }
  }
  sleep(1);
  printf ("=============[Before start the nns edge]=================\n\n");
  ret = nns_edge_start (client_h);
  if (NNS_EDGE_ERROR_NONE != ret) {
    printf ("Failed to start query client.\n");
    goto done;
  }

  sleep (1);

  if (NNS_EDGE_NODE_TYPE_QUERY_CLIENT == opt_data.node_type) {
    ret = nns_edge_connect (client_h, opt_data.dest_host, opt_data.dest_port);
    if (NNS_EDGE_ERROR_NONE != ret) {
      printf ("Failed to connect to query server.\n");
      goto done;
    }
  }

  ret = _prepare_edge_data (&data_h);
  if (NNS_EDGE_ERROR_NONE != ret) {
    printf ("Failed to prepare to nns edge data.\n");
    goto done;
  }

  received = 0;
  for (i = 0; i < 50U; i++) {
    nns_edge_send (client_h, data_h);
    usleep (100000);
  }

  ret = nns_edge_data_destroy (data_h);
  if (NNS_EDGE_ERROR_NONE != ret) {
    printf ("Failed to destroy the edge data.");
    goto done;
  }

  /* Wait for responding data (20 seconds) */
  retry = 0U;
  do {
    usleep (100000);
    if (received > 0)
      break;
  } while (NNS_EDGE_NODE_TYPE_QUERY_CLIENT == opt_data.node_type &&
	    retry++ < 200U);

  printf ("\n\n[[[DEBUG]] Received data: %u\n\n", received);

done:
  wifi_manager_deinit();
  wifi_signal_deinit();
  nns_edge_release_handle (client_h);
  free (client_host);
  free (opt_data.dest_host);
  free (opt_data.topic);
	free (opt_data.ssid);
	free (opt_data.wifi_pw);

  return ret;
}
