<?php

namespace App\Models;

use Database\Factories\EventTypeFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;

/**
 * A kind of activity in the calendar: theory, pool, open water and so on.
 * Administrators maintain the list; hidden types are not offered for new events.
 * A type may have a parent (one level only), e.g. «Бассейн» → «Начальный уровень».
 */
#[Fillable(['parent_id', 'name', 'is_active'])]
class EventType extends Model
{
    /** @use HasFactory<EventTypeFactory> */
    use HasFactory;

    /**
     * The parent is always loaded, because the full name of a child needs it.
     *
     * @var list<string>
     */
    protected $with = ['parent'];

    /**
     * @var array<string, mixed>
     */
    protected $attributes = [
        'is_active' => true,
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'sort_order' => 'integer',
            'is_active' => 'boolean',
        ];
    }

    /**
     * New types go to the end of the list.
     */
    protected static function booted(): void
    {
        static::creating(function (EventType $eventType): void {
            $eventType->sort_order ??= (int) static::query()->max('sort_order') + 1;
        });

        static::updating(function (EventType $eventType): void {
            if ($eventType->isDirty('parent_id')) {
                $eventType->sort_order = (int) static::query()->max('sort_order') + 1;
            }
        });
    }

    /**
     * The parent type, if this one is a child.
     *
     * @return BelongsTo<EventType, $this>
     */
    public function parent(): BelongsTo
    {
        return $this->belongsTo(self::class, 'parent_id');
    }

    /**
     * The types that are children of this one.
     *
     * @return HasMany<EventType, $this>
     */
    public function children(): HasMany
    {
        return $this->hasMany(self::class, 'parent_id');
    }

    /**
     * The exercises attached to this type. Events of a child type are also offered
     * the exercises of its parent; see Exercise::forEventType().
     *
     * @return BelongsToMany<Exercise, $this>
     */
    public function exercises(): BelongsToMany
    {
        return $this->belongsToMany(Exercise::class);
    }

    /**
     * The name with the parent in front of it, as shown in lists and in the calendar.
     *
     * @return Attribute<string, never>
     */
    protected function fullName(): Attribute
    {
        return Attribute::get(fn (): string => $this->parent ? "{$this->parent->name} / {$this->name}" : $this->name);
    }

    /**
     * Every type in list order, each parent followed by its children.
     *
     * @return Collection<int, EventType>
     */
    public static function inTreeOrder(): Collection
    {
        $types = static::query()->ordered()->get();
        $children = $types->whereNotNull('parent_id')->groupBy('parent_id');

        return $types->whereNull('parent_id')->flatMap(
            fn (EventType $type): Collection => collect([$type])->concat($children->get($type->id, [])),
        )->values();
    }

    /**
     * The ids of the type and of its children, for filtering events by a parent type.
     *
     * @return list<int>
     */
    public function idsWithChildren(): array
    {
        return [$this->id, ...$this->children()->pluck('id')->all()];
    }

    /**
     * @param  Builder<EventType>  $query
     */
    #[Scope]
    protected function ordered(Builder $query): void
    {
        $query->orderBy('sort_order')->orderBy('id');
    }

    /**
     * @param  Builder<EventType>  $query
     */
    #[Scope]
    protected function active(Builder $query): void
    {
        $query->where('is_active', true);
    }

    /**
     * Move the type one place up the list. Does nothing when it is already first.
     * Returns whether it moved.
     */
    public function moveUp(): bool
    {
        return $this->moveBy(-1);
    }

    /**
     * Move the type one place down the list. Does nothing when it is already last.
     * Returns whether it moved.
     */
    public function moveDown(): bool
    {
        return $this->moveBy(1);
    }

    /**
     * Swap the type with its neighbour among the types with the same parent and renumber
     * them, so that positions stay consecutive even if two types ever shared a number.
     */
    private function moveBy(int $offset): bool
    {
        $moved = DB::transaction(function () use ($offset): bool {
            $ids = static::query()->where('parent_id', $this->parent_id)->ordered()->lockForUpdate()->pluck('id')->all();

            $from = array_search($this->id, $ids, true);
            $to = $from === false ? null : $from + $offset;

            if ($to === null || ! array_key_exists($to, $ids)) {
                return false;
            }

            [$ids[$from], $ids[$to]] = [$ids[$to], $ids[$from]];

            foreach ($ids as $index => $id) {
                static::query()->whereKey($id)->update(['sort_order' => $index + 1]);
            }

            return true;
        });

        $this->refresh();

        return $moved;
    }
}
