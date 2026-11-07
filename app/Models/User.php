<?php

namespace App\Models;

use App\Enums\Role;
use App\Enums\ScheduleRange;
use App\Notifications\ResetPasswordNotification;
use Database\Factories\UserFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Casts\AsEnumCollection;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

/**
 * An account. A user holds one or more roles: an administrator manages the system,
 * an instructor teaches and appears in the calendar. One person can be both.
 */
#[Fillable(['name', 'last_name', 'email', 'password', 'phone', 'roles', 'is_active', 'color', 'notes'])]
#[Hidden(['password', 'remember_token'])]
class User extends Authenticatable
{
    /** @use HasFactory<UserFactory> */
    use HasFactory, Notifiable;

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
            'roles' => AsEnumCollection::of(Role::class),
            'is_active' => 'boolean',
            'schedule_range' => ScheduleRange::class,
        ];
    }

    /**
     * How far ahead the user looks at an instructor's schedule: their own choice, or the default.
     */
    public function preferredScheduleRange(): ScheduleRange
    {
        return $this->schedule_range ?? ScheduleRange::default();
    }

    /**
     * The user who created this account.
     *
     * @return BelongsTo<User, $this>
     */
    public function creator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    /**
     * The equipment assigned to the user as an instructor.
     *
     * @return HasMany<Equipment, $this>
     */
    public function equipment(): HasMany
    {
        return $this->hasMany(Equipment::class, 'instructor_id');
    }

    /**
     * Limit the query to accounts with the instructor role, administrators who teach included.
     *
     * @param  Builder<User>  $query
     */
    public function scopeInstructors(Builder $query): void
    {
        $query->whereJsonContains('roles', Role::Instructor->value);
    }

    /**
     * The name and the last name in one line.
     */
    public function fullName(): string
    {
        return trim("{$this->name} {$this->last_name}");
    }

    public function hasRole(Role $role): bool
    {
        return $this->roles?->contains($role) ?? false;
    }

    /**
     * Send the password reset link through the queue instead of during the request.
     */
    public function sendPasswordResetNotification(#[\SensitiveParameter] $token): void
    {
        $this->notify(new ResetPasswordNotification($token));
    }

    public function isAdmin(): bool
    {
        return $this->hasRole(Role::Admin);
    }

    public function isInstructor(): bool
    {
        return $this->hasRole(Role::Instructor);
    }

    /**
     * The user's roles in one line, e.g. "Администратор, инструктор".
     */
    public function rolesLabel(): string
    {
        $labels = collect(Role::cases())
            ->filter(fn (Role $role): bool => $this->hasRole($role))
            ->map(fn (Role $role): string => $role->label())
            ->values();

        return $labels->map(fn (string $label, int $index): string => $index === 0 ? $label : mb_strtolower($label))->implode(', ');
    }
}
