#include "StdInc.h"

#include "Hooking.FlexStruct.h"
#include "Hooking.Patterns.h"
#include "Hooking.Stubs.h"

static int32_t g_entryCountOffset;

static void (*g_origSelectEntry)(hook::FlexStruct*, uint32_t);

static void SelectEntry(hook::FlexStruct* self, uint32_t entryIndex)
{
	if (entryIndex >= self->Get<uint32_t>(g_entryCountOffset))
	{
		static bool hasWarnedBefore = false;

		if (!hasWarnedBefore)
		{
			hasWarnedBefore = true;

			trace("SelectEntry: rejected out-of-range entry index %u\n", entryIndex);
		}

		return;
	}

	g_origSelectEntry(self, entryIndex);
}

static HookFunction hookFunction([]
{
	auto matches = hook::pattern("3B 91 ? ? ? ? 72 ? F3 C3 48 83 EC ? 48 8B 81 ? ? ? ? 8B D2 48 8B 14 D0 48 85 D2 74 ? 48 81 C1 ? ? ? ?");

	if (matches.empty())
	{
		return;
	}

	auto location = matches.get(0).get<uint8_t>(0);

	const auto entryCountOffset = *(int32_t*)(location + 2);
	const auto entryStateOffset = *(int32_t*)(location + 35);

	if (entryCountOffset <= entryStateOffset)
	{
		return;
	}

	g_entryCountOffset = entryCountOffset;

	g_origSelectEntry = hook::trampoline(location + 10, SelectEntry);
});
