<script setup>
defineProps({
    processing: { type: Boolean, default: false },
});
</script>

<template>
    <button
        type="submit"
        :disabled="processing"
        class="inline-flex items-center justify-center rounded-md bg-sea-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-sea-700 disabled:cursor-wait disabled:opacity-60"
    >
        <slot />
    </button>
</template>
