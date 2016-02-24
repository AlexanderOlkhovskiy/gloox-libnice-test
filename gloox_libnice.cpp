#include <cstdio>
#include <string>

#include <stdlib.h>
#include <string.h>

// gloox
#include <gloox/client.h>
#include <gloox/connectionlistener.h>
#include <gloox/disco.h>
#include <gloox/error.h>
#include <gloox/loghandler.h>
#include <gloox/message.h>
#include <gloox/jinglecontent.h>
#include <gloox/jingleiceudp.h>
#include <gloox/jinglesessionhandler.h>
#include <gloox/jinglesessionmanager.h>
using namespace gloox;
using namespace gloox::Jingle;

// libnice
#include <glib.h>
#if GLIB_CHECK_VERSION(2, 36, 0)
#include <gio/gnetworking.h>
#endif
#include <nice/agent.h>

enum Mode { HOST, JOIN };

class GlooxConnectionListener;

static guint g_StreamID;
static GlooxConnectionListener *g_glooxConnectionListenerInstance;
static Mode g_mode;
static JID g_hostJID;
static Session *g_activeSession;
static SessionManager *g_sessionManager;
static Client *g_glooxClient;
static NiceAgent *g_agent;

static const gchar *state_name[] = {"disconnected", "gathering", "connecting",
                                    "connected", "ready", "failed"};

static const std::string XMLNS_JINGLE_DEMO_GAME = "urn:xmpp:jingle:apps:demo-game:0";

static const int COMPONENTS_COUNT = 1;
static const int COMPONENT_ID = 1;

class DemoGameData: public Plugin {
public:
  DemoGameData(): Plugin(PluginUser) {}

  DemoGameData(const Tag* tag): Plugin(PluginUser) {
    if (!tag) {
      return;
    }
  }

  const std::string& filterString() const {
    static const std::string filter = "content/description[@xmlns='" + XMLNS_JINGLE_DEMO_GAME + "']";
    return filter;
  }

  Tag* tag() const {
    Tag* r = new Tag("description", XMLNS, XMLNS_JINGLE_DEMO_GAME);
    return r;
  }

  Plugin* newInstance(const Tag* tag) const {
    return new DemoGameData(tag);
  }

  Plugin* clone() const {
    return new DemoGameData(*this);
  }
};

class GlooxConnectionListener: public ConnectionListener, public SessionHandler, public LogHandler {
public:
  GlooxConnectionListener(Client *newGlooxClient, Mode newMode, char* hostJIDStr, NiceAgent *agent) :
    m_agent(agent) {

    g_glooxClient = newGlooxClient;
    g_mode = newMode;
    g_activeSession = NULL;

    g_sessionManager = new SessionManager(g_glooxClient, this);

    // Register plugins to allow gloox parse them in incoming sessions
    g_sessionManager->registerPlugin(new Content());
    g_sessionManager->registerPlugin(new DemoGameData());
    g_sessionManager->registerPlugin(new ICEUDP());

    if (hostJIDStr != NULL) {
      g_hostJID = JID(hostJIDStr);
    }

    g_glooxConnectionListenerInstance = this;

    g_StreamID = createStream();
  }

  int createStream() {
    // Create a new stream with required components count and start gathering candidates
    int createdStreamID = nice_agent_add_stream (m_agent, COMPONENTS_COUNT);
    nice_agent_gather_candidates (m_agent, createdStreamID);

    // Attach I/O callback the component to ensure that:
    // 1) agent gets its STUN packets (not delivered to cb_nice_recv)
    // 2) you get your own data
    nice_agent_attach_recv (m_agent, createdStreamID, COMPONENT_ID, NULL,
                           cb_nice_recv, NULL);

    return createdStreamID;
  }

  virtual void onConnect()
  {
    printf("Connected!\n");

    if (g_mode == JOIN) {
      initSession();
    }
  }

  virtual void onDisconnect(ConnectionError e)
  {
    printf("message_test: disconnected: %d\n", e);
    if(e == ConnAuthenticationFailed)
      printf("auth failed. reason: %d\n", g_glooxClient->authError());
  }

  virtual bool onTLSConnect(const CertInfo& info)
  {
    time_t from( info.date_from );
    time_t to( info.date_to );

    printf("status: %d\nissuer: %s\npeer: %s\nprotocol: %s\nmac: %s\ncipher: %s\ncompression: %s\n"
           "from: %s\nto: %s\n",
           info.status, info.issuer.c_str(), info.server.c_str(),
           info.protocol.c_str(), info.mac.c_str(), info.cipher.c_str(),
           info.compression.c_str(), ctime(&from), ctime(&to));
    return true;
  }

  void processJingleData(const Session::Jingle *jingle) {
    const Content *content = dynamic_cast<const Content*>(jingle->plugins().front());
    if (content == NULL) {
      printf("Failed to retrieve Jingle content\n");
      return;
    }
    const DemoGameData *gameData = dynamic_cast<const DemoGameData*>(content->findPlugin(PluginUser));
    if (gameData == NULL) {
      printf("Failed to retrieve Jingle game data\n");
      return;
    }
    const ICEUDP *iceUdp = dynamic_cast<const ICEUDP*>(content->findPlugin(PluginICEUDP));
    if (iceUdp == NULL) {
      printf("Failed to retrieve Jingle ICE-UDP data\n");
      return;
    }

    GSList *remote_candidates = NULL;
    for (ICEUDP::Candidate candidate: iceUdp->candidates()) {

      NiceCandidate *cand = NULL;

      NiceCandidateType ntype;
      switch(candidate.type) {
      case ICEUDP::Host:
        ntype = NICE_CANDIDATE_TYPE_HOST;
        break;
      case ICEUDP::ServerReflexive:
        ntype = NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
        break;
      case ICEUDP::PeerReflexive:
        ntype = NICE_CANDIDATE_TYPE_PEER_REFLEXIVE;
        break;
      case ICEUDP::Relayed:
        ntype = NICE_CANDIDATE_TYPE_RELAYED;
        break;
      }
      cand = nice_candidate_new(ntype);

      cand->component_id = std::stoi(candidate.component);
      cand->stream_id = g_StreamID;
      cand->transport = NICE_CANDIDATE_TRANSPORT_UDP;
      strncpy(cand->foundation, candidate.foundation.c_str(), NICE_CANDIDATE_MAX_FOUNDATION);
      cand->foundation[NICE_CANDIDATE_MAX_FOUNDATION - 1] = 0;
      cand->priority = candidate.priority;

      if (!nice_address_set_from_string(&cand->addr, candidate.ip.c_str())) {
        g_message("failed to parse addr: %s", candidate.ip.c_str());
        nice_candidate_free(cand);
        cand = NULL;
        return;
      }

      nice_address_set_port(&cand->addr, candidate.port);
      remote_candidates = g_slist_prepend(remote_candidates, cand);
    }

    const gchar *ufrag = iceUdp->ufrag().c_str();
    const gchar *pwd = iceUdp->pwd().c_str();
    if (!nice_agent_set_remote_credentials(m_agent, g_StreamID, ufrag, pwd)) {
      g_message("failed to set remote credentials");
      return;
    }

    // Note: this will trigger the start of negotiation.
    if (nice_agent_set_remote_candidates(m_agent, g_StreamID, COMPONENT_ID,
        remote_candidates) < 1) {
      g_message("failed to set remote candidates");
      return;
    }
  }

  virtual void handleSessionAction (Action action, Session *session, const Session::Jingle *jingle) {
    printf("Session action: %d\n", action);

    if ((g_mode == HOST && action == SessionInitiate)
        || (g_mode == JOIN && action == SessionAccept)) {
      processJingleData(jingle);
      g_activeSession = session;
      if (g_mode == HOST && action == SessionInitiate) {
        acceptSession();
      }
    }
  }

  virtual void handleSessionActionError (Action action, Session *session, const Error *error) {
    printf("Session action error: type=%d code=%d\n", error->type(), error->error());
  }

  virtual void handleIncomingSession (Session *session) {
    printf("Incoming session from %s\n", session->initiator().full().c_str());
  }

  virtual void handleLog( LogLevel level, LogArea area, const std::string& message )
  {
    printf("log: level: %d, area: %d, %s\n", level, area, message.c_str());
  }

  static void cb_candidate_gathering_done(NiceAgent *agent, guint _stream_id,
      gpointer data)
  {
      g_debug("SIGNAL candidate gathering done\n");

      g_glooxClient->connect(false);
  }

  static void cb_component_state_changed(NiceAgent *agent, guint _stream_id,
      guint component_id, guint state,
      gpointer data)
  {

      printf("SIGNAL: state changed %d %d %s[%d]\n",
        _stream_id, component_id, state_name[state], state);

      if (state == NICE_COMPONENT_STATE_READY) {
        NiceCandidate *local, *remote;

        // Get current selected candidate pair and print IP address used
        if (nice_agent_get_selected_pair (agent, _stream_id, component_id,
                    &local, &remote)) {
          gchar ipaddr[INET6_ADDRSTRLEN];

          nice_address_to_string(&local->addr, ipaddr);
          printf("\nNegotiation complete: ([%s]:%d,",
              ipaddr, nice_address_get_port(&local->addr));
          nice_address_to_string(&remote->addr, ipaddr);
          printf(" [%s]:%d)\n", ipaddr, nice_address_get_port(&remote->addr));
        }
        std::string msg = (g_mode == JOIN)? "(message from client)" : "(message from host)";
        nice_agent_send(agent, g_StreamID, COMPONENT_ID, msg.length(), msg.c_str());
      }
  }

  static void cb_new_selected_pair(NiceAgent *agent, guint _stream_id,
      guint component_id, gchar *lfoundation,
      gchar *rfoundation, gpointer data)
  {
      printf("SIGNAL: selected pair %s %s\n", lfoundation, rfoundation);
  }

  static void cb_nice_recv(NiceAgent *agent, guint _stream_id, guint component_id,
      guint len, gchar *buf, gpointer data)
  {
    if (len == 1 && buf[0] == '\0') {
      return;
    }
    printf("Message received: %.*s\n", len, buf);
    fflush(stdout);
  }

  static void initSession() {
    sendIq(SessionInitiate);
  }

  static void acceptSession() {
    sendIq(SessionAccept);
  }

  static void sendIq(Action action) {
    if (action != SessionInitiate && action != SessionAccept) {
      printf("Invalid session action in sendIq\n");
      return;
    }

    gchar *local_ufrag = NULL;
    gchar *local_pwd = NULL;
    GSList *lcands = NULL;
    GSList *item;
    gchar ip[NICE_ADDRESS_STRING_LEN];
    gchar base_ip[NICE_ADDRESS_STRING_LEN];
    ICEUDP::Type type;
    int id;
    int network;

    lcands = nice_agent_get_local_candidates(g_agent, g_StreamID, COMPONENT_ID);
    nice_agent_get_local_credentials(g_agent, g_StreamID, &local_ufrag, &local_pwd);

    if (action == SessionInitiate) {
      g_activeSession = g_sessionManager->createSession(g_hostJID, g_glooxConnectionListenerInstance);
    }

    DemoGameData *gameData = new DemoGameData();

    int candidate_generation = 0;

    ICEUDP::CandidateList *candidateList = new ICEUDP::CandidateList();
    for (item = lcands, id=0; item; item = item->next, id++) {
        NiceCandidate *c = (NiceCandidate *)item->data;

        nice_address_to_string(&c->addr, ip);
        nice_address_to_string(&c->base_addr, base_ip);
        switch(c->type) {
        case NICE_CANDIDATE_TYPE_HOST:
          type = ICEUDP::Host;
          break;
        case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
          type = ICEUDP::ServerReflexive;
          break;
        case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
          type = ICEUDP::PeerReflexive;
          break;
        case NICE_CANDIDATE_TYPE_RELAYED:
          type = ICEUDP::Relayed;
          break;
        }

        /*
         * Unlike ICE-UDP, ICE-CORE doesn't specify id and network values,
         * so they aren't present in NiceCandidate,
         * see http://xmpp.org/extensions/xep-0176.html#protocol-syntax
         */
        network = 0;

        candidateList->push_back(ICEUDP::Candidate
            {std::to_string(c->component_id), c->foundation,
             std::to_string(candidate_generation), std::to_string(id),
             ip, std::to_string(network), (int)nice_address_get_port(&c->addr),
             (int)c->priority, "udp", base_ip, (int)nice_address_get_port(&c->base_addr), type}
        );
    }
    ICEUDP *iceUdp = new ICEUDP(local_pwd, local_ufrag, *candidateList);

    PluginList *pluginList = new PluginList();
    pluginList->push_back(gameData);
    pluginList->push_back(iceUdp);
    Content *content = new Content(std::string("game-data"), *pluginList);

    if (action == SessionInitiate) {
      bool result = g_activeSession->sessionInitiate(content);
      printf("Session init result: %d\n", result);
    }
    else if (action == SessionAccept) {
      bool result = g_activeSession->sessionAccept(content);
      printf("Session accept result: %d\n", result);
    }
  }

private:
    NiceAgent *m_agent;

};

void printUsageAndExit(char *programName) {
  printf("Usage:\n");
  printf("  %s host <jid> <psd>\n", programName);
  printf("  %s join <jid> <psd> <host_jid>\n", programName);

  exit(EXIT_FAILURE);
}

static GMainLoop *gloop;

int main(int argc, char* argv[]) {
  if (argc != 4 && argc != 5) {
    printUsageAndExit(argv[0]);
  }
  Mode mode;
  char *programName = argv[0];
  char *modeStr = argv[1];
  char *jidStr = argv[2];
  char *psd = argv[3];
  char *hostJidStr = NULL;

  if (strcmp(modeStr, "host") == 0) {
    mode = HOST;
  }
  else if (strcmp(modeStr, "join") == 0) {
    mode = JOIN;
    hostJidStr = argv[4];
  }
  else {
    printUsageAndExit(programName);
  }

  gloop = g_main_loop_new(NULL, FALSE);

#if GLIB_CHECK_VERSION(2, 36, 0)
  g_networking_init();
#else
  g_type_init();
#endif

  // Create a nice agent
  g_agent = nice_agent_new(g_main_loop_get_context (gloop),
                                    NICE_COMPATIBILITY_RFC5245);
  if (g_agent == NULL)
      g_error("Failed to create agent");

  // FIXME: STUN server address should be configurable
  g_object_set(g_agent, "stun-server", "217.10.68.152", NULL);
  g_object_set(g_agent, "stun-server-port", 3478, NULL);

  // Client is sending offer, so it's the controlling agent
  bool controlling = (mode == JOIN);
  g_object_set(g_agent, "controlling-mode", controlling, NULL);

  // Connect the signals
  g_signal_connect (G_OBJECT (g_agent), "candidate-gathering-done",
                    G_CALLBACK (GlooxConnectionListener::cb_candidate_gathering_done), NULL);
  g_signal_connect (G_OBJECT (g_agent), "component-state-changed",
                    G_CALLBACK (GlooxConnectionListener::cb_component_state_changed), NULL);
  g_signal_connect (G_OBJECT (g_agent), "new-selected-pair",
                    G_CALLBACK (GlooxConnectionListener::cb_new_selected_pair), NULL);

  JID jid(jidStr);
  g_glooxClient = new Client(jid, psd);
  GlooxConnectionListener glooxConnectionListener(g_glooxClient, mode, hostJidStr, g_agent);

  g_glooxClient->registerConnectionListener(&glooxConnectionListener);
  g_glooxClient->logInstance().registerLogHandler(LogLevelWarning, LogAreaAll, &glooxConnectionListener);

  while (true) {
    g_main_context_iteration(g_main_loop_get_context(gloop), FALSE);
    g_glooxClient->recv(0);
  }

  g_main_loop_unref(gloop);
  g_object_unref(g_agent);

  delete(g_glooxClient);
  return 0;
}
