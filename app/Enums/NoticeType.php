<?php

namespace App\Enums;

use App\Models\User;

/**
 * The kinds of notices, one per domain event; the value is the event's class name, as kept
 * in `notices.type`. People choose by these which notices reach them in Telegram.
 *
 * A personal type can concern a particular user, e.g. their event was moved or equipment was
 * assigned to them, so anyone may get it. The rest concern nobody in particular: only an
 * administrator, who sees every notice, can get them.
 */
enum NoticeType: string
{
    case CalendarEventCreated = 'CalendarEventCreated';
    case CalendarEventRescheduled = 'CalendarEventRescheduled';
    case CalendarEventUpdated = 'CalendarEventUpdated';
    case CalendarEventInstructorsChanged = 'CalendarEventInstructorsChanged';
    case CalendarEventCancelled = 'CalendarEventCancelled';
    case CalendarEventCompleted = 'CalendarEventCompleted';
    case CalendarEventReopened = 'CalendarEventReopened';

    case ClientBooked = 'ClientBooked';
    case BookingStatusChanged = 'BookingStatusChanged';
    case BookingUpdated = 'BookingUpdated';
    case BookingExercisesChanged = 'BookingExercisesChanged';

    case EquipmentCreated = 'EquipmentCreated';
    case EquipmentAssigned = 'EquipmentAssigned';
    case EquipmentStatusChanged = 'EquipmentStatusChanged';
    case EquipmentUpdated = 'EquipmentUpdated';
    case EquipmentCategoryCreated = 'EquipmentCategoryCreated';
    case EquipmentCategoryUpdated = 'EquipmentCategoryUpdated';

    case UserCreated = 'UserCreated';
    case UserUpdated = 'UserUpdated';
    case UserActivated = 'UserActivated';
    case UserDeactivated = 'UserDeactivated';
    case UserRolesChanged = 'UserRolesChanged';
    case UserPasswordChanged = 'UserPasswordChanged';

    case ClientCreated = 'ClientCreated';
    case ClientUpdated = 'ClientUpdated';
    case ClientDeleted = 'ClientDeleted';
    case CommunicationCreated = 'CommunicationCreated';
    case CommunicationUpdated = 'CommunicationUpdated';
    case CommunicationDeleted = 'CommunicationDeleted';

    case EventTypeCreated = 'EventTypeCreated';
    case EventTypeUpdated = 'EventTypeUpdated';
    case EventTypesReordered = 'EventTypesReordered';
    case ExerciseCreated = 'ExerciseCreated';
    case ExerciseUpdated = 'ExerciseUpdated';
    case ExerciseEventTypesChanged = 'ExerciseEventTypesChanged';
    case ExercisesReordered = 'ExercisesReordered';
    case LocationCreated = 'LocationCreated';
    case LocationUpdated = 'LocationUpdated';

    /**
     * Human-readable kind of notice shown in the settings.
     */
    public function label(): string
    {
        return match ($this) {
            self::CalendarEventCreated => 'Новое занятие',
            self::CalendarEventRescheduled => 'Занятие перенесено',
            self::CalendarEventUpdated => 'Изменены данные занятия',
            self::CalendarEventInstructorsChanged => 'Изменён состав инструкторов',
            self::CalendarEventCancelled => 'Занятие отменено',
            self::CalendarEventCompleted => 'Занятие проведено',
            self::CalendarEventReopened => 'Занятие снова запланировано',
            self::ClientBooked => 'Клиент записан на занятие',
            self::BookingStatusChanged => 'Изменён статус клиента на занятии',
            self::BookingUpdated => 'Изменена запись клиента',
            self::BookingExercisesChanged => 'Изменены упражнения клиента',
            self::EquipmentCreated => 'Добавлено снаряжение',
            self::EquipmentAssigned => 'Снаряжение закреплено или откреплено',
            self::EquipmentStatusChanged => 'Изменён статус снаряжения',
            self::EquipmentUpdated => 'Изменены данные снаряжения',
            self::EquipmentCategoryCreated => 'Новая категория снаряжения',
            self::EquipmentCategoryUpdated => 'Изменена категория снаряжения',
            self::UserCreated => 'Создана учётная запись',
            self::UserUpdated => 'Изменены данные учётной записи',
            self::UserActivated => 'Учётная запись активирована',
            self::UserDeactivated => 'Учётная запись деактивирована',
            self::UserRolesChanged => 'Изменены роли',
            self::UserPasswordChanged => 'Изменён пароль',
            self::ClientCreated => 'Новый клиент',
            self::ClientUpdated => 'Изменены данные клиента',
            self::ClientDeleted => 'Клиент удалён',
            self::CommunicationCreated => 'Записан контакт с клиентом',
            self::CommunicationUpdated => 'Изменён контакт с клиентом',
            self::CommunicationDeleted => 'Удалён контакт с клиентом',
            self::EventTypeCreated => 'Новый тип занятий',
            self::EventTypeUpdated => 'Изменён тип занятий',
            self::EventTypesReordered => 'Изменён порядок типов занятий',
            self::ExerciseCreated => 'Новое упражнение',
            self::ExerciseUpdated => 'Изменено упражнение',
            self::ExerciseEventTypesChanged => 'Изменены типы занятий упражнения',
            self::ExercisesReordered => 'Изменён порядок упражнений',
            self::LocationCreated => 'Новая локация',
            self::LocationUpdated => 'Изменена локация',
        };
    }

    /**
     * The heading the type is listed under in the settings.
     */
    public function group(): string
    {
        return match ($this) {
            self::CalendarEventCreated, self::CalendarEventRescheduled, self::CalendarEventUpdated,
            self::CalendarEventInstructorsChanged, self::CalendarEventCancelled, self::CalendarEventCompleted,
            self::CalendarEventReopened => 'Занятия',
            self::ClientBooked, self::BookingStatusChanged, self::BookingUpdated, self::BookingExercisesChanged => 'Клиенты на занятиях',
            self::EquipmentCreated, self::EquipmentAssigned, self::EquipmentStatusChanged, self::EquipmentUpdated,
            self::EquipmentCategoryCreated, self::EquipmentCategoryUpdated => 'Снаряжение',
            self::UserCreated, self::UserUpdated, self::UserActivated, self::UserDeactivated,
            self::UserRolesChanged, self::UserPasswordChanged => 'Учётные записи',
            self::ClientCreated, self::ClientUpdated, self::ClientDeleted,
            self::CommunicationCreated, self::CommunicationUpdated, self::CommunicationDeleted => 'Клиенты',
            self::EventTypeCreated, self::EventTypeUpdated, self::EventTypesReordered, self::ExerciseCreated,
            self::ExerciseUpdated, self::ExerciseEventTypesChanged, self::ExercisesReordered,
            self::LocationCreated, self::LocationUpdated => 'Справочники',
        };
    }

    /**
     * Whether a notice of this type can concern a particular user, so that it is worth choosing
     * for someone who is not an administrator.
     */
    public function isPersonal(): bool
    {
        return match ($this) {
            self::EquipmentCategoryCreated, self::EquipmentCategoryUpdated,
            self::ClientCreated, self::ClientUpdated, self::ClientDeleted,
            self::CommunicationCreated, self::CommunicationUpdated, self::CommunicationDeleted,
            self::EventTypeCreated, self::EventTypeUpdated, self::EventTypesReordered, self::ExerciseCreated,
            self::ExerciseUpdated, self::ExerciseEventTypesChanged, self::ExercisesReordered,
            self::LocationCreated, self::LocationUpdated => false,
            default => true,
        };
    }

    /**
     * The types the user can choose: all of them for an administrator, the personal ones otherwise.
     *
     * @return list<self>
     */
    public static function availableTo(User $user): array
    {
        if ($user->isAdmin()) {
            return self::cases();
        }

        return array_values(array_filter(self::cases(), fn (self $type): bool => $type->isPersonal()));
    }

    /**
     * The types the user can choose, by their groups, for the settings page.
     *
     * @return list<array{label: string, types: list<array{value: string, label: string, personal: bool}>}>
     */
    public static function groupedFor(User $user): array
    {
        $groups = [];

        foreach (self::availableTo($user) as $type) {
            $groups[$type->group()][] = ['value' => $type->value, 'label' => $type->label(), 'personal' => $type->isPersonal()];
        }

        return array_map(
            fn (string $label, array $types): array => ['label' => $label, 'types' => $types],
            array_keys($groups),
            array_values($groups),
        );
    }
}
