#include "eap_methods.h"

int eap_get_iterations(EAP__METHOD method)
{
	switch (method)
	{
		case EAP__EDHOC:
			return 5;
		case EAP__PSK:
			return 4;
		default:
			return 5;
	}
}