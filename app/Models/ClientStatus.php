<?php

namespace App\Models;

use App\Models\Concerns\HasListPosition;
use Database\Factories\ClientStatusFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * Where a client is in their training, e.g. «Проходит курс закрытой воды» or «Ждёт сертификат».
 * A client has one status at a time, a status is shared by many clients.
 * Administrators maintain the list; a hidden status can not be newly chosen
 * but stays on the clients who already have it.
 */
#[Fillable(['name', 'is_active'])]
class ClientStatus extends Model
{
    /** @use HasFactory<ClientStatusFactory> */
    use HasFactory, HasListPosition;

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
     * The clients who currently have this status.
     *
     * @return HasMany<Client, $this>
     */
    public function clients(): HasMany
    {
        return $this->hasMany(Client::class);
    }

    /**
     * @param  Builder<ClientStatus>  $query
     */
    #[Scope]
    protected function active(Builder $query): void
    {
        $query->where('is_active', true);
    }
}
