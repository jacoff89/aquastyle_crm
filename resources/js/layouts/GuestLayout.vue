<script setup>
import { usePage } from '@inertiajs/vue3';
import DiveFlag from '../components/DiveFlag.vue';

defineProps({
    title: { type: String, required: true },
    description: { type: String, default: '' },
});

const page = usePage();
</script>

<template>
    <div class="flex min-h-full flex-col">
        <header class="bg-depth-900 px-4 py-5 sm:px-8">
            <div class="mx-auto flex max-w-md items-center gap-3">
                <DiveFlag :size="28" />
                <span class="text-lg font-semibold text-white">{{ page.props.appName }}</span>
            </div>
        </header>

        <main class="flex flex-1 justify-center px-4 py-10 sm:py-16">
            <div class="w-full max-w-md">
                <h1 class="text-2xl font-semibold tracking-tight text-ink">{{ title }}</h1>
                <p v-if="description" class="mt-2 text-sm leading-6 text-muted">{{ description }}</p>

                <div class="mt-8">
                    <slot />
                </div>
            </div>
        </main>
    </div>
</template>
