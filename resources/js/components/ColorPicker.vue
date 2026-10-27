<script setup>
// Готовая палитра для быстрого выбора и системный выбор для любого другого цвета.
defineProps({
    id: { type: String, required: true },
    invalid: { type: Boolean, default: false },
});

const model = defineModel({ type: String, default: '#0891b2' });

const palette = ['#0891b2', '#2563eb', '#7c3aed', '#db2777', '#dc2626', '#ea580c', '#ca8a04', '#16a34a', '#0d9488', '#475569'];
</script>

<template>
    <div class="flex flex-wrap items-center gap-2">
        <button
            v-for="color in palette"
            :key="color"
            type="button"
            class="size-8 rounded-full ring-offset-2 transition-shadow"
            :class="model === color ? 'ring-2 ring-ink' : 'hover:ring-2 hover:ring-line'"
            :style="{ backgroundColor: color }"
            :aria-label="`Цвет ${color}`"
            :aria-pressed="model === color"
            @click="model = color"
        />
        <input
            :id="id"
            v-model="model"
            type="color"
            class="size-8 cursor-pointer rounded-md border bg-white p-0.5"
            :class="invalid ? 'border-flag' : 'border-line'"
            :aria-invalid="invalid"
            aria-label="Другой цвет"
        />
        <span class="ml-1 text-sm text-muted">{{ model }}</span>
    </div>
</template>
