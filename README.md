# Contexte
Développement d'un système de détection d'intrusion dans le cadre d'un projet scolaire, afin d'acquérir une approche de base pour la capture et le filtrage de paquets réseau avec libpcap.

# Fonctionnement
Avant tout, nous devons récupérer l'adresse réseau et le masque de sous-réseau à l'aide de la fonction pcap_lookupnet().

Pour commencer, nous utilisons la bibliothèque libpcap pour créer un gestionnaire de capture, nommé handle, en appelant la fonction pcap_create(). Ensuite, nous configurons le délai d'attente pour la capture des paquets avec pcap_set_timeout(). Une fois ces paramètres définis, nous activons le gestionnaire de capture à l'aide de pcap_activate().

Nous vérifions ensuite que la connexion est bien de type Ethernet en utilisant la fonction pcap_datalink().

Après cela, nous compilons un filtre avec la fonction pcap_compile() pour spécifier les types de paquets que nous souhaitons capturer. Ce filtre est ensuite appliqué avec pcap_setfilter() afin de ne capturer que les paquets correspondants.

La fonction pcap_loop() est ensuite utilisée pour démarrer la capture et lire le nombre souhaité de paquets. Chaque fois qu'un paquet est capturé, cette fonction appelle la fonction de rappel my_packet_handler. Dans my_packet_handler, nous utilisons read_rules() pour lire les règles définies dans le fichier "rules.txt" et les stocker dans une structure de données.

Nous appelons ensuite populate_packet_ds() pour extraire l'en-tête et les données de chaque paquet capturé et les placer dans une structure appelée frame. La fonction rules_matcher() compare cette structure frame avec les règles chargées depuis "rules.txt". Si les deux correspondent, un message d'alerte est envoyé via syslog().

Enfin, les informations sur les paquets capturés sont affichées, permettant ainsi une analyse plus approfondie.
