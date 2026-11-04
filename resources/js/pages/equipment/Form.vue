<script setup>
import { Link, useForm } from '@inertiajs/vue3';
import { computed } from 'vue';
import FormField from '../../components/FormField.vue';
import PrimaryButton from '../../components/PrimaryButton.vue';
import SelectInput from '../../components/SelectInput.vue';
import TextArea from '../../components/TextArea.vue';
import TextInput from '../../components/TextInput.vue';
import AppLayout from '../../layouts/AppLayout.vue';

const props = defineProps({
    /** Снаряжение для правки или null для нового. */
    item: { type: Object, default: null },
    /** Категории: { id, name }. */
    categories: { type: Array, required: true },
    /** Все локации: { id, name, isActive }. */
    locations: { type: Array, required: true },
    /** Все инструкторы: { id, name, isActive }. */
    instructors: { type: Array, required: true },
    statuses: { type: Array, required: true },
});

const isEditing = computed(() => props.item !== null);

const form = useForm({
    name: props.item?.name ?? '',
    category_id: props.item?.categoryId ?? '',
    inventory_number: props.item?.inventoryNumber ?? '',
    size: props.item?.size ?? '',
    status: props.item?.status ?? 'in_use',
    location_id: props.item?.locationId ?? '',
    instructor_id: props.item?.instructorId ?? '',
    notes: props.item?.notes ?? '',
});

/** Скрытые локации и отключённые инструкторы предлагаются, только если уже стоят у снаряжения. */
const locationOptions = computed(() => props.locations.filter((location) => location.isActive || location.id === props.item?.locationId));

const instructorOptions = computed(() =>
    props.instructors.filter((instructor) => instructor.isActive || instructor.id === props.item?.instructorId),
);

const submit = () => {
    if (isEditing.value) {
        form.put(`/equipment/${props.item.id}`);
    } else {
        form.post('/equipment');
    }
};
</script>

<template>
    <AppLayout :title="isEditing ? item.name : 'Новое снаряжение'">
        <form class="max-w-2xl space-y-8" novalidate @submit.prevent="submit">
            <section class="space-y-5 rounded-lg border border-line bg-white p-6" aria-labelledby="equipment-heading">
                <h2 id="equipment-heading" class="text-lg font-semibold">Снаряжение</h2>

                <div class="grid gap-5 sm:grid-cols-[2fr_1fr]">
                    <FormField id="name" label="Название" hint="Например, «Регулятор Apeks XTX50»." :error="form.errors.name">
                        <TextInput id="name" v-model="form.name" autocomplete="off" required :invalid="Boolean(form.errors.name)" />
                    </FormField>

                    <FormField
                        id="category_id"
                        label="Категория"
                        :hint="categories.length ? '' : 'Категории добавляются на странице реестра.'"
                        :error="form.errors.category_id"
                    >
                        <SelectInput id="category_id" v-model="form.category_id" :invalid="Boolean(form.errors.category_id)">
                            <option value="">Без категории</option>
                            <option v-for="category in categories" :key="category.id" :value="category.id">{{ category.name }}</option>
                        </SelectInput>
                    </FormField>
                </div>

                <div class="grid gap-5 sm:grid-cols-3">
                    <FormField id="inventory_number" label="Инвентарный номер" :error="form.errors.inventory_number">
                        <TextInput id="inventory_number" v-model="form.inventory_number" autocomplete="off" :invalid="Boolean(form.errors.inventory_number)" />
                    </FormField>

                    <FormField id="size" label="Размер" :error="form.errors.size">
                        <TextInput id="size" v-model="form.size" autocomplete="off" :invalid="Boolean(form.errors.size)" />
                    </FormField>

                    <FormField id="status" label="Состояние" :error="form.errors.status">
                        <SelectInput id="status" v-model="form.status" :invalid="Boolean(form.errors.status)">
                            <option v-for="status in statuses" :key="status.value" :value="status.value">{{ status.label }}</option>
                        </SelectInput>
                    </FormField>
                </div>

                <div class="grid gap-5 sm:grid-cols-2">
                    <FormField id="location_id" label="Локация" hint="Где хранится." :error="form.errors.location_id">
                        <SelectInput id="location_id" v-model="form.location_id" :invalid="Boolean(form.errors.location_id)">
                            <option value="">Без локации</option>
                            <option v-for="location in locationOptions" :key="location.id" :value="location.id">
                                {{ location.name }}{{ location.isActive ? '' : ' (скрыта)' }}
                            </option>
                        </SelectInput>
                    </FormField>

                    <FormField id="instructor_id" label="Инструктор" hint="За кем закреплено." :error="form.errors.instructor_id">
                        <SelectInput id="instructor_id" v-model="form.instructor_id" :invalid="Boolean(form.errors.instructor_id)">
                            <option value="">Не закреплено</option>
                            <option v-for="instructor in instructorOptions" :key="instructor.id" :value="instructor.id">
                                {{ instructor.name }}{{ instructor.isActive ? '' : ' (отключён)' }}
                            </option>
                        </SelectInput>
                    </FormField>
                </div>

                <FormField id="notes" label="Заметки" :error="form.errors.notes">
                    <TextArea id="notes" v-model="form.notes" :invalid="Boolean(form.errors.notes)" />
                </FormField>
            </section>

            <div class="flex items-center gap-4">
                <PrimaryButton :processing="form.processing">
                    {{ isEditing ? 'Сохранить изменения' : 'Добавить снаряжение' }}
                </PrimaryButton>
                <Link href="/equipment" class="text-sm text-muted hover:text-ink">Отмена</Link>
            </div>
        </form>
    </AppLayout>
</template>
