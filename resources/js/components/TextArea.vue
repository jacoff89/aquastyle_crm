<script setup>
defineProps({
    invalid: { type: Boolean, default: false },
});

const model = defineModel({ type: String, default: '' });
</script>

<template>
    <textarea
        v-model="model"
        rows="3"
        class="block w-full rounded-md border bg-white px-3 py-2 text-base text-ink placeholder:text-muted/70 focus:outline-none focus-visible:ring-2 focus-visible:ring-sea-600/30 sm:text-sm"
        :class="invalid ? 'border-flag' : 'border-line focus-visible:border-sea-600'"
        :aria-invalid="invalid"
    />
</template>
