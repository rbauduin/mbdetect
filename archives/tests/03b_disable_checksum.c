
#include <stdio.h>
#define CSUM_CTRL_FILE "/proc/sys/net/mptcp/mptcp_checksum"

// writes a 0 to mptcp_enabled file under /proc/sys
// returns the value received from the fprintf call
int disable_csum() {
	int res;				// result of fprintf call
	FILE *f = fopen(CSUM_CTRL_FILE, "w");  
	if (f == NULL)
	{
		printf("Error opening file! Do you have root powers and is this kernel mptcp capable?\n");
		return -1;
	}
	res = fprintf(f, "%d", 0);		
	fclose(f);
	return res ;
}

// writes a 1 to mptcp_enabled file under /proc/sys
// returns the value received from the fprintf call
int enable_csum() {
	int res;				// result of fprintf call
	FILE *f = fopen(CSUM_CTRL_FILE, "w");
	if (f == NULL)
	{
		printf("Error opening file! Do you have root powers and is this kernel mptcp capable?\n");
		return -1;
	}
	res = fprintf(f, "%d", 1);
	fclose(f);
	return res ;
}

// looks at the file mptcp_enabled under /proc/sys and write the opposite value.
int toggle_csum() {
	// - res is the result of the call to fprintf
	// - current is return value from fgetc, giving an 
	//   unsigned char casted to an int
	int res,current;
	FILE *f = fopen(CSUM_CTRL_FILE, "r");
	current = fgetc(f);
	fclose(f);
	// as current is an unsigned char casted to an int, 
	// use %c to print it as a char
	printf("before-change value is %c\n",current);
	if (current==48) { // 48 = ASCII code of 0
		enable_csum();
	}
	else {
		disable_csum();
	}

}


int main(void)
{
	toggle_csum();
	return 0;
}
