#include <iostream>
#include <ctime>

int main()
{
	time_t lt = time(NULL);
	auto ts = localtime(&lt);
	printf("Current date and time:\n%02d.%02d.%04d\n%02d:%02d:%02d\n", ts->tm_mday, ts->tm_mon + 1, ts->tm_year + 1900, ts->tm_hour, ts->tm_min, ts->tm_sec);

	fgetc(stdin);

    return 0;
}
