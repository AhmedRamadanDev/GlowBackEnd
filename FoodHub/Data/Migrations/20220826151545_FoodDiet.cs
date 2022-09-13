using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FoodHub.Data.Migrations
{
    public partial class FoodDiet : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Foods_diets_dietId",
                table: "Foods");

            migrationBuilder.DropIndex(
                name: "IX_Foods_dietId",
                table: "Foods");

            migrationBuilder.DropColumn(
                name: "dietId",
                table: "Foods");

            migrationBuilder.CreateTable(
                name: "Fooddiet",
                columns: table => new
                {
                    DietsId = table.Column<int>(type: "int", nullable: false),
                    FoodsId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Fooddiet", x => new { x.DietsId, x.FoodsId });
                    table.ForeignKey(
                        name: "FK_Fooddiet_diets_DietsId",
                        column: x => x.DietsId,
                        principalTable: "diets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_Fooddiet_Foods_FoodsId",
                        column: x => x.FoodsId,
                        principalTable: "Foods",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Fooddiet_FoodsId",
                table: "Fooddiet",
                column: "FoodsId");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Fooddiet");

            migrationBuilder.AddColumn<int>(
                name: "dietId",
                table: "Foods",
                type: "int",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Foods_dietId",
                table: "Foods",
                column: "dietId");

            migrationBuilder.AddForeignKey(
                name: "FK_Foods_diets_dietId",
                table: "Foods",
                column: "dietId",
                principalTable: "diets",
                principalColumn: "Id");
        }
    }
}
