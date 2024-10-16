# FONCTIONNEMENT
Pour commencer, à l’aide de la bibliothèque libpcap on crée un gestionnaire et on le 
paramètre. Ensuite on l’active et on applique les filtres pour récupérer les paquets qu’on
souhaite capturer. Puis, on fait appel à une fonction pcap_loop() qui va lire le nombre de 
paquets qu’on souhaite avoir. Cette fonction utilise une fonction de rappel dans laquelle on 
fait appel à la fonction read_rules() qui va lire les contenus du fichier « rules.txt » et l’insérer 
dans la structure. Ensuite on fait appel à une fonction populate_packet_ds() qui va récupérer 
l’en-tête et les données de chaque paquet pour les mettre dans une structure frame. Puis on 
appelle la fonction rules_matcher() qui va comparer la structure frame à la structure 
contenant les règles provenant du fichier rules.txt. Si ces deux structures « match » alors on 
envoie un message d’alerte grâce à syslog(). Et enfin, on affiche les contenus des paquets.
