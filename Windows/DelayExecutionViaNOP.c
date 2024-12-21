#include <Windows.h>
#include <stdio.h>

BOOL DelayNOP(DWORD dwMiliseconds)
{
	DWORD T0, T1, TW, dwAverage = 0;
	DWORD dwTimes[25];

	for (int i = 0; i < 25; i++)
	{
		TW = GetTickCount64();
		for (int j = 0; j < 10000000; j++)
			__nop();
		dwTimes[i] = GetTickCount64() - TW;
		dwAverage += dwTimes[i];
	}
	dwAverage = dwAverage / 25;
    
	// roughly halving it gets it much closer (lots of extra istructions in benchmark loop)
	printf("[i] Delaying Execution Using \"__nop\" For ~%d Miliseconds\n", dwMiliseconds);
	T0 = GetTickCount64();
	for (int i = 0; i < (dwMiliseconds / dwAverage) * 4500000; i++)
		__nop();
	T1 = GetTickCount64();
	printf("\t >> T1 - T0 = %d\n", T1 - T0);

	if (T1 - T0 < dwMiliseconds)
		return FALSE;

	return TRUE;
}

int main()
{
	DelayNOP(5000);

	return 0;
}
