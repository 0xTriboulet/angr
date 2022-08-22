#include <stdio.h>

int one(){
	int i = 0;
	for(i=0;i<50;i++){
		i += i;
	}
	return i;
}

int main(){
	int a = 0;
	printf("enter a number:\n");
	scanf("%d",&a);
	if(a == (5 +one())){
		printf("SUCCESS!\n\n");
	}else{
		printf("FAIL!\n\n");
	}
	
	return 0;
}
