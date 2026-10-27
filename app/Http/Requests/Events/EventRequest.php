<?php

namespace App\Http\Requests\Events;

use App\Enums\EventStatus;
use App\Enums\Role;
use App\Models\Event;
use App\Models\EventType;
use App\Models\User;
use Illuminate\Database\Query\Builder;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Carbon;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Exists;
use Illuminate\Validation\Validator;

/**
 * Fields shared by creating and editing an event. Times are wall-clock time in the
 * application time zone, as "Y-m-d H:i". Hidden event types and deactivated instructors
 * are not offered for new events, but an event that already has them keeps them.
 *
 * A clash with another event of the same instructor is not checked here: it is
 * a warning the controller shows, and `confirm_conflicts` saves the event anyway.
 */
abstract class EventRequest extends FormRequest
{
    public const DATETIME_FORMAT = 'Y-m-d H:i';

    private const MAX_DURATION_HOURS = 24;

    /**
     * @var list<int>|null
     */
    private ?array $currentInstructorIds = null;

    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            'event_type_id' => ['required', 'integer', $this->eventTypeRule()],
            'title' => ['nullable', 'string', 'max:255'],
            'starts_at' => ['required', 'date_format:'.self::DATETIME_FORMAT],
            'ends_at' => ['required', 'date_format:'.self::DATETIME_FORMAT, 'after:starts_at'],
            'location' => ['nullable', 'string', 'max:255'],
            'capacity' => ['nullable', 'integer', 'min:1', 'max:500'],
            'notes' => ['nullable', 'string', 'max:2000'],
            'lead_instructor_id' => ['required', 'integer', $this->instructorRule()],
            'assistant_ids' => ['array', 'max:20'],
            'assistant_ids.*' => ['integer', 'distinct', 'different:lead_instructor_id', $this->instructorRule()],
            'confirm_conflicts' => ['boolean'],
        ];
    }

    /**
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'event_type_id.exists' => 'Выберите тип занятия из списка.',
            'lead_instructor_id.required' => 'Выберите ведущего инструктора.',
            'lead_instructor_id.exists' => 'Ведущий инструктор не найден или отключён.',
            'assistant_ids.*.exists' => 'Помощник не найден или отключён.',
            'assistant_ids.*.different' => 'Ведущий инструктор не может быть одновременно помощником.',
            'ends_at.after' => 'Занятие должно заканчиваться позже, чем начинается.',
        ];
    }

    /**
     * @return array<int, callable(Validator): void>
     */
    public function after(): array
    {
        return [
            function (Validator $validator): void {
                if ($validator->errors()->hasAny(['starts_at', 'ends_at'])) {
                    return;
                }

                if ($this->startsAt()->diffInHours($this->endsAt()) > self::MAX_DURATION_HOURS) {
                    $validator->errors()->add('ends_at', 'Занятие не может длиться больше суток.');
                }
            },
        ];
    }

    public function startsAt(): Carbon
    {
        return Carbon::createFromFormat(self::DATETIME_FORMAT, $this->string('starts_at')->toString())->startOfMinute();
    }

    public function endsAt(): Carbon
    {
        return Carbon::createFromFormat(self::DATETIME_FORMAT, $this->string('ends_at')->toString())->startOfMinute();
    }

    public function leadInstructorId(): int
    {
        return $this->integer('lead_instructor_id');
    }

    /**
     * @return list<int>
     */
    public function assistantIds(): array
    {
        return array_values(array_map('intval', $this->validated('assistant_ids', [])));
    }

    /**
     * Every instructor of the event, lead first.
     *
     * @return list<int>
     */
    public function instructorIds(): array
    {
        return array_values(array_unique([$this->leadInstructorId(), ...$this->assistantIds()]));
    }

    /**
     * Columns of the `events` table filled from the request.
     *
     * @return array<string, mixed>
     */
    public function eventAttributes(): array
    {
        return [
            'event_type_id' => $this->integer('event_type_id'),
            'title' => $this->validated('title'),
            'starts_at' => $this->startsAt(),
            'ends_at' => $this->endsAt(),
            'location' => $this->validated('location'),
            'capacity' => $this->validated('capacity'),
            'notes' => $this->validated('notes'),
        ];
    }

    public function status(): EventStatus
    {
        return EventStatus::Planned;
    }

    protected function prepareForValidation(): void
    {
        $this->merge([
            'title' => $this->trimmedOrNull('title'),
            'location' => $this->trimmedOrNull('location'),
            'assistant_ids' => $this->input('assistant_ids') ?? [],
        ]);
    }

    /**
     * The event being edited, whose current type and instructors stay allowed.
     */
    protected function editedEvent(): ?Event
    {
        return null;
    }

    private function eventTypeRule(): Exists
    {
        $currentTypeId = $this->editedEvent()?->event_type_id;

        return Rule::exists(EventType::class, 'id')->where(fn (Builder $query) => $query->where(fn (Builder $query) => $query
            ->where('is_active', true)
            ->when($currentTypeId, fn (Builder $query, int $id) => $query->orWhere('id', $id))));
    }

    private function instructorRule(): Exists
    {
        $this->currentInstructorIds ??= $this->editedEvent()?->instructors()->pluck('users.id')->all() ?? [];
        $currentInstructorIds = $this->currentInstructorIds;

        return Rule::exists(User::class, 'id')->where(fn (Builder $query) => $query
            ->where('role', Role::Instructor->value)
            ->where(fn (Builder $query) => $query
                ->where('is_active', true)
                ->when($currentInstructorIds !== [], fn (Builder $query) => $query->orWhereIn('id', $currentInstructorIds))));
    }

    private function trimmedOrNull(string $key): ?string
    {
        $value = trim((string) $this->input($key));

        return $value === '' ? null : $value;
    }
}
