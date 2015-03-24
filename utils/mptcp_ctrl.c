#include <stdio.h>
#define MPTCP_CTRL_FILE "/proc/sys/net/mptcp/mptcp_enabled"
#define CSUM_CTRL_FILE "/proc/sys/net/mptcp/mptcp_checksum"

int current_setting(char *path) {
	// - current is return value from fgetc, giving an 
	//   unsigned char casted to an int
	int current;
	FILE *f = fopen(path, "r");
	if (f==NULL) {
		return 0;
	}
	current = fgetc(f);
	fclose(f);
	if (current==48) {
		return 0;
	}
	else {
		return 1;
	}

}
// returns 0 if mptcp inactive, 1 otherwise
int is_setting_active(char *path) {
	// - current is return value from fgetc, giving an 
	//   unsigned char casted to an int
	int current = current_setting(path);
	return current!=48; // 48 = int value of '0'
}

// writes a 0 to mptcp_enabled file under /proc/sys
// returns the previous value of the setting, or -1 in case of error
int set_setting(char *path,int value) {
	int res;				// result of fprintf call
	int previous = current_setting(path);
	FILE *f = fopen(path, "w");  
	if (f == NULL)
	{
		printf("Error opening file! Do you have root powers and is this kernel mptcp capable?\n");
		return -1;
	}
	res = fprintf(f, "%d", value);		
	fclose(f);
	return previous ;
}
int disable_setting(char *path){
	return set_setting(path, 0);
}

int enable_setting(char *path){
	return set_setting(path, 1);
}

int toggle_setting(char *path){
	int previous=current_setting(path);
	if (previous) {
		set_setting(path,0);
	}
	else {
		set_setting(path,1);
	}
	return previous;
}

int can_toggle_setting(char *path) {
	FILE *f = fopen(path, "w");
	if (f == NULL)
	{
		printf("Error opening file! Do you have root powers and is this kernel mptcp capable?\n");
		return 0;
	}
	fclose(f);
	return 1;
}
// get current mptcp setting
int current_mptcp(){
	return current_setting(MPTCP_CTRL_FILE);
}

int set_mptcp(int value) {
	return set_setting(MPTCP_CTRL_FILE,value);
}

// returns 0 if mptcp inactive, 1 otherwise
int is_mptcp_active() {
	return is_setting_active(MPTCP_CTRL_FILE);
}

// writes a 0 to mptcp_enabled file under /proc/sys
// returns the value received from the fprintf call
int disable_mptcp() {
	return disable_setting(MPTCP_CTRL_FILE);
}


int can_toggle_mptcp() {
	return can_toggle_setting(MPTCP_CTRL_FILE);
}

// writes a 1 to mptcp_enabled file under /proc/sys
// returns the value received from the fprintf call
int enable_mptcp() {
	return enable_setting(MPTCP_CTRL_FILE);
}
// looks at the file mptcp_enabled under /proc/sys and write the opposite value.
int toggle_mptcp() {
	return toggle_setting(MPTCP_CTRL_FILE);
}

// get current csum setting
int current_csum(){
	return current_setting(CSUM_CTRL_FILE);
}

// returns 0 if csum inactive, 1 otherwise
int is_csum_active() {
	return is_setting_active(CSUM_CTRL_FILE);
}
// writes a 0 to csum control file under /proc/sys
// returns the previous value
int disable_csum() {
	return disable_setting(CSUM_CTRL_FILE);
}

int enable_csum() {
	return enable_setting(CSUM_CTRL_FILE);
}
int set_csum(int value) {
	return set_setting(CSUM_CTRL_FILE,value);
}
