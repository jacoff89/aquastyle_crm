<?php

namespace App\Models;

use App\Enums\Role;
use Database\Factories\UserFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Casts\AsEnumCollection;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

/**
 * An account. A user holds one or more roles: an administrator manages the system,
 * an instructor teaches and appears in the calendar. One person can be both.
 */
#[Fillable(['name', 'email', 'password', 'phone', 'roles', 'is_active', 'color', 'notes'])]
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
        ];
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
     * Limit the query to accounts with the instructor role, administrators who teach included.
     *
     * @param  Builder<User>  $query
     */
    public function scopeInstructors(Builder $query): void
    {
        $query->whereJsonContains('roles', Role::Instructor->value);
    }

    public function hasRole(Role $role): bool
    {
        return $this->roles?->contains($role) ?? false;
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
