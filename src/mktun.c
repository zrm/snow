#include<sys/types.h>
#include<pwd.h>
#include<sys/ioctl.h>
#include<linux/if_tun.h>
#include<net/if.h>
#include<stdio.h>
#include<string.h>
#include<sys/stat.h>
#include<fcntl.h>


int main(int argc, char* argv[])
{
	if(argc < 3) {
		printf("Usage: %s <tun device name> <username> [clone device name]\n", argv[0]);
		return -1;
	}
	const char *clonedev, default_clonedev[] = "/dev/net/tun";
	if(argc > 3)
		clonedev = argv[3];
	else
		clonedev = default_clonedev;
	
	struct passwd* name = getpwnam(argv[2]);
	if(name == NULL) {
		perror("Username not found or error getting UID");
		return -1;
	}


	// Create tun interface 
	int tun_fd;
	struct ifreq ifr;
	if( ( tun_fd = open(clonedev, O_RDWR) ) < 0 ) {
		perror("Could not open clone device");
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	if(strlen(argv[1]) >= IFNAMSIZ) return -1;
	strcpy(ifr.ifr_name, argv[1]);
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if(ioctl(tun_fd, TUNSETIFF, (void *) &ifr) < 0) {
		perror("Could not create tun interface");
	}

	// Set owner and make interface persistent
	if(ioctl(tun_fd, TUNSETOWNER, name->pw_uid) < 0) {
		perror("Could not set tun interface owner uid");
		return -1;
	}
	if(ioctl(tun_fd, TUNSETGROUP, name->pw_gid) < 0) {
		perror("Could not set tun interface owner gid");
		return -1;
	}
	if(ioctl(tun_fd, TUNSETPERSIST, 1) < 0) {
		perror("Could not make tun interface persistent");
		return -1;
	}
	printf("Created device %s for uid %d gid %d\n", ifr.ifr_name, name->pw_uid, name->pw_gid);
	return 0;
}


