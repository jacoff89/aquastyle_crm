<?php

namespace App\Events;

use BackedEnum;
use DateTimeInterface;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Database\Eloquent\Model;
use JsonSerializable;
use Stringable;
use UnitEnum;

/**
 * What one save changed in a model: the old and the new value of every changed attribute.
 *
 * Values are kept as plain scalars and lists (an enum as its value, a date as "Y-m-d H:i:s"
 * in the application time zone), so a change set survives the queue and can be stored as JSON
 * in the activity log and read back with fromArray().
 *
 * Timestamps, secrets and derived columns are left out: they are not changes a person makes.
 * A password change is announced by its own event instead.
 *
 * @implements Arrayable<string, array{old: mixed, new: mixed}>
 */
final class ChangeSet implements Arrayable, JsonSerializable
{
    /**
     * @var list<string>
     */
    private const IGNORED = ['created_at', 'updated_at', 'password', 'remember_token', 'phone_digits'];

    /**
     * @param  array<string, array{old: mixed, new: mixed}>  $changes
     */
    private function __construct(private readonly array $changes) {}

    /**
     * The changes made by the model's last save. Call it right after the save,
     * before anything saves the model again.
     */
    public static function fromModel(Model $model): self
    {
        $previous = (clone $model)->setRawAttributes(array_merge($model->getAttributes(), $model->getPrevious()));
        $changes = [];

        foreach (array_keys($model->getChanges()) as $attribute) {
            if (in_array($attribute, self::IGNORED, true)) {
                continue;
            }

            $changes[$attribute] = [
                'old' => self::normalize($previous->getAttribute($attribute)),
                'new' => self::normalize($model->getAttribute($attribute)),
            ];
        }

        return new self($changes);
    }

    /**
     * A change set read back from storage, the reverse of toArray().
     *
     * @param  array<string, array{old: mixed, new: mixed}>  $changes
     */
    public static function fromArray(array $changes): self
    {
        return new self($changes);
    }

    /**
     * The model's attributes in the same plain form, for an event about a record that is gone.
     *
     * @return array<string, mixed>
     */
    public static function snapshotOf(Model $model): array
    {
        $snapshot = [];

        foreach (array_keys($model->getAttributes()) as $attribute) {
            if (! in_array($attribute, self::IGNORED, true)) {
                $snapshot[$attribute] = self::normalize($model->getAttribute($attribute));
            }
        }

        return $snapshot;
    }

    /**
     * Whether any of the given attributes changed.
     */
    public function has(string ...$attributes): bool
    {
        foreach ($attributes as $attribute) {
            if (array_key_exists($attribute, $this->changes)) {
                return true;
            }
        }

        return false;
    }

    public function old(string $attribute): mixed
    {
        return $this->changes[$attribute]['old'] ?? null;
    }

    public function new(string $attribute): mixed
    {
        return $this->changes[$attribute]['new'] ?? null;
    }

    /**
     * @return list<string>
     */
    public function attributes(): array
    {
        return array_keys($this->changes);
    }

    public function isEmpty(): bool
    {
        return $this->changes === [];
    }

    public function isNotEmpty(): bool
    {
        return ! $this->isEmpty();
    }

    /**
     * @return array<string, array{old: mixed, new: mixed}>
     */
    public function toArray(): array
    {
        return $this->changes;
    }

    /**
     * @return array<string, array{old: mixed, new: mixed}>
     */
    public function jsonSerialize(): array
    {
        return $this->changes;
    }

    /**
     * Bring a cast attribute value to a plain scalar or list.
     */
    private static function normalize(mixed $value): mixed
    {
        return match (true) {
            $value === null, is_scalar($value) => $value,
            $value instanceof BackedEnum => $value->value,
            $value instanceof UnitEnum => $value->name,
            $value instanceof DateTimeInterface => $value->format('Y-m-d H:i:s'),
            $value instanceof Arrayable => array_map(self::normalize(...), $value->toArray()),
            is_array($value) => array_map(self::normalize(...), $value),
            $value instanceof Stringable => (string) $value,
            default => $value,
        };
    }
}
